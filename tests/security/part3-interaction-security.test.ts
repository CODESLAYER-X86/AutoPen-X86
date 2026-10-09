/**
 * Part 3 security tests (spec §82.4) — the interaction layer must fail
 * closed: SSRF defences, scope bypass, oversized payloads, secret leakage
 * and browser context isolation are adversarially verified.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateId } from '@aegis/shared';
import { createPool, UsersRepository } from '@aegis/database';
import {
  buildInteractionStack,
  gatewayContext,
  seedEngagement,
  type InteractionStack,
} from '../integration/part3-helpers.js';
import { HttpEngine, DEFAULT_NETWORK_POLICY } from '@aegis/target-http';
import { mapRequestRow } from '@aegis/target-http';
import { startLabApp } from '../fixtures/labApp.js';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

let stack: InteractionStack;
let engagement: { engagementId: string; identityA: string; identityB: string; anonymous: string };
let labUrl: string;

beforeAll(async () => {
  const pool = createPool(TEST_DATABASE_URL, { max: 4 });
  const users = new UsersRepository(pool);
  const user = await users.create({
    email: `p3-sec-${generateId('USR').slice(4).toLowerCase()}@test.local`,
    name: 'Part3 Security Test',
    passwordHash: 'not-a-real-hash',
  });
  stack = await buildInteractionStack({ pool, browser: { downloadsEnabled: true } });
  engagement = await seedEngagement(stack, user.id);
  labUrl = stack.lab.url;
}, 120_000);

afterAll(async () => {
  if (stack) {
    await stack.browser.closeEngagement(engagement.engagementId).catch(() => undefined);
    await stack.lab.close().catch(() => undefined);
    await stack.pool.end().catch(() => undefined);
  }
}, 120_000);

describe('scope enforcement (§82.4)', () => {
  it('rejects out-of-scope hosts at the gateway before any network I/O', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: 'http://evil.attacker.example.com/admin' },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('SCOPE_VIOLATION');
    }
  }, 30_000);

  it('refuses to follow redirects to out-of-scope hosts (§51)', async () => {
    // Fail-closed: the redirect hop re-validation REJECTS the exchange
    // before any connection to the out-of-scope host is attempted.
    await expect(
      stack.engine.send(
        {
          engagementId: engagement.engagementId,
          method: 'GET',
          url: `${labUrl}/redirect/external`,
          headers: [],
          body: null,
          identityId: null,
        },
        stack.scope,
      ),
    ).rejects.toThrowError(/scope/i);
  }, 30_000);

  it('blocks excessive redirect loops (§51)', async () => {
    await expect(
      stack.engine.send(
        {
          engagementId: engagement.engagementId,
          method: 'GET',
          url: `${labUrl}/redirect/loop`,
          headers: [],
          body: null,
          identityId: null,
        },
        stack.scope,
      ),
    ).rejects.toThrowError(/redirect/i);
  }, 30_000);

  it('rejects malformed URLs with typed errors', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: 'not-a-valid-url' },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['INVALID_URL', 'SCOPE_VIOLATION', 'TOOL_INPUT_INVALID']).toContain(result.error.code);
    }
  }, 30_000);
});

describe('SSRF defences (§50-§52, §82.4)', () => {
  it('denies loopback and private IPs under the production network policy', async () => {
    const restrictiveScope = {
      ...stack.scope,
      // scope ALLOWS the host, but the network policy must still deny:
      allowed_hosts: [...stack.scope.allowed_hosts, 'internal.example.com'],
      allowed_ports: [...stack.scope.allowed_ports, 80],
    };
    const engine = new HttpEngine({ networkPolicy: DEFAULT_NETWORK_POLICY });

    // Direct loopback literal (scope allows 127.0.0.1, policy denies).
    await expect(
      engine.send(
        { engagementId: 'ENG_SEC1', method: 'GET', url: `${labUrl}/api/status`, headers: [], body: null, identityId: null },
        restrictiveScope,
      ),
    ).rejects.toThrowError(/loopback/i);

    // Private network via hostname resolution: internal.example.com could
    // resolve anywhere — DNS resolution happens and is classified.
    await expect(
      engine.send(
        { engagementId: 'ENG_SEC1', method: 'GET', url: 'http://internal.example.com/x', headers: [], body: null, identityId: null },
        restrictiveScope,
      ),
    ).rejects.toThrowError();
  }, 60_000);
});

describe('resource limits (§48, §82.4)', () => {
  it('truncates oversized HTTP responses with the explicit flag', async () => {
    const exchange = await stack.engine.send(
      {
        engagementId: engagement.engagementId,
        method: 'GET',
        url: `${labUrl}/api/oversized`,
        headers: [],
        body: null,
        identityId: null,
      },
      stack.scope,
    );
    expect(exchange.response.truncated).toBe(true);
    expect(exchange.response.bodyBytes.byteLength).toBeLessThanOrEqual(2_097_152);
  }, 60_000);

  it('records oversized WebSocket messages with truncated flags (§36, §48)', async () => {
    const ctx = await stack.browser.getContextHandle(engagement.engagementId, null);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'navigate',
      url: `${labUrl}/login`,
    }, stack.scope);
    const page = [...ctx.pages.keys()][0]!;
    await page.evaluate((url: string) => {
      return new Promise<void>((resolve) => {
        const ws = new WebSocket(url);
        ws.onopen = () => {
          ws.send('SEND_OVERSIZED'); // server replies with 2 MiB
          setTimeout(() => {
            ws.close();
            resolve();
          }, 800);
        };
        ws.onerror = () => resolve();
      });
    }, `${labUrl.replace('http', 'ws')}/ws`);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    // Force a drain boundary.
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    const connections = await stack.repos.websockets.listConnections(engagement.engagementId);
    const oversized = connections.find((c: Record<string, unknown>) => String(c.url).includes('/ws'));
    expect(oversized).toBeDefined();
    const messages = await stack.repos.websockets.listMessages(oversized!.id as string, 50);
    const big = messages.find((m: Record<string, unknown>) => Number(m.byte_size) > 262_144);
    expect(big).toBeDefined();
    expect(big?.truncated).toBe(true);
    expect(String(big?.payload_preview ?? '').length).toBeLessThanOrEqual(262_144 + 16);
    await stack.browser.closeContext(engagement.engagementId, ctx.id);
  }, 120_000);
});

describe('tool permission violations (§69, §82.4)', () => {
  it('blocks browser tools when the browser permission is absent', async () => {
    const result = await stack.gateway.execute(
      'browser.navigate',
      { context_id: 'CTX_ANY', action: 'navigate', url: `${labUrl}/login` },
      gatewayContext(stack, engagement.engagementId, {
        permissions: { network: true, browser: false, destructive: false },
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('TOOL_BROWSER_FORBIDDEN');
    }
  }, 30_000);

  it('blocks network tools without scope', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${labUrl}/api/status` },
      gatewayContext(stack, engagement.engagementId, { scope: null }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('SCOPE_NOT_CONFIGURED');
    }
  }, 30_000);

  it('blocks artifact access across engagements (§65)', async () => {
    // Store evidence in the engagement, then request it under a foreign ctx.
    const evidence = await stack.evidence.store({
      engagement_id: engagement.engagementId,
      type: 'RAW',
      source: 'test',
      content: 'secret-content',
    });
    const foreignCtx = gatewayContext(stack, 'ENG_FOREIGN000000001');
    const result = await stack.gateway.execute(
      'artifact.read',
      { artifact_ref: evidence.id, offset: 0, limit_bytes: 64 },
      foreignCtx,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['ARTIFACT_ENGAGEMENT_MISMATCH', 'ARTIFACT_NOT_FOUND']).toContain(result.error.code);
    }
  }, 30_000);
});

describe('secret leakage (§66, §82.4)', () => {
  it('never persists cookie values or auth headers in request records', async () => {
    // Authenticated request with a cookie session.
    const login = await stack.engine.send(
      {
        engagementId: engagement.engagementId,
        method: 'POST',
        url: `${labUrl}/login`,
        headers: [{ name: 'content-type', value: 'application/x-www-form-urlencoded' }],
        body: {
          body_type: 'FORM_URLENCODED',
          fields: [
            { name: 'username', value: 'admin' },
            { name: 'password', value: 'admin-secret' },
          ],
        },
        identityId: null,
      },
      stack.scope,
    );
    const setCookie = (login.response.headers as Array<{ name: string; value: string }>).find(
      (h) => h.name.toLowerCase() === 'set-cookie',
    );
    const token = /LABSESS=([^;]+)/.exec(setCookie?.value ?? '')?.[1] ?? '';
    expect(token).not.toBe('');

    await stack.sessionManager.registerAuthState({
      engagementId: engagement.engagementId,
      identityId: engagement.identityA,
      material: {
        kind: 'COOKIE',
        cookies: [{ name: 'LABSESS', value: token, domain: '127.0.0.1', path: '/', secure: false, httpOnly: true, sameSite: null, expires: null }],
      },
    });

    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${labUrl}/api/me`, identity_id: engagement.identityA },
      gatewayContext(stack, engagement.engagementId, { identityId: engagement.identityA }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const requestId = (result.output as { request_id: string }).request_id;

    // The DB row must NOT contain the raw cookie value.
    const rawRow = await stack.repos.httpRequests.findById(requestId);
    expect(rawRow).not.toBeNull();
    const serialized = JSON.stringify(rawRow);
    expect(serialized).not.toContain(token);

    // The mapped contract record never carries the session credential:
    // session-injected headers are applied at execution time only (§19,
    // §26) and user-supplied sensitive headers are redacted to «redacted».
    const record = mapRequestRow(rawRow!);
    const cookieHeader = record.headers.find((h) => h.name.toLowerCase() === 'cookie');
    expect(cookieHeader === undefined || cookieHeader?.value === '«redacted»').toBe(true);

    // The raw evidence bundle DOES contain it (authorized, §66) but the
    // tool output preview never echoes Set-Cookie values.
    const output = result.output as { body_preview: string | null };
    expect(output.body_preview ?? '').not.toContain(token);
  }, 30_000);

  it('stores sensitive storage values only as secret references', async () => {
    const ctx = await stack.browser.getContextHandle(engagement.engagementId, null);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'navigate',
      url: `${labUrl}/login`,
    }, stack.scope);
    await stack.browser.captureContextState(engagement.engagementId, ctx.id);
    const storageRows = await stack.repos.storageEntries.listByContext(ctx.id);
    // The lab app writes non-sensitive keys; any sensitive-named key must
    // have its value redacted with a secret reference attached.
    for (const row of storageRows) {
      if (row.is_sensitive) {
        expect(row.value_redacted).toBe('«redacted»');
        expect(row.secret_reference).not.toBeNull();
      }
    }
    const cookieRows = await stack.repos.cookies.listByContext(ctx.id);
    for (const row of cookieRows) {
      const serialized = JSON.stringify(row);
      expect(serialized).not.toMatch(/LABSESS=sess-/);
    }
    await stack.browser.closeContext(engagement.engagementId, ctx.id);
  }, 60_000);
});

describe('browser context leakage (§3, §29, §82.4)', () => {
  it('never shares cookies between identity contexts', async () => {
    // Log in inside ctxA.
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${labUrl}/login`,
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Username' },
      value: 'usera',
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Password' },
      value: 'password-a',
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'click',
      selector: { strategy: 'role', value: 'button', role: 'button', name: 'Login' },
    }, stack.scope);
    await new Promise((resolve) => setTimeout(resolve, 800));

    // ctxB: fresh anonymous-style context for another identity.
    const ctxB = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityB);
    const anonymousPage = [...ctxB.pages.keys()][0] ?? (await ctxB.pw.newPage());
    await anonymousPage.goto(`${labUrl}/api/me`).catch(() => undefined);
    const cookiesA = await ctxA.pw.cookies();
    const cookiesB = await ctxB.pw.cookies();
    const sessionA = cookiesA.find((cookie: { name: string }) => cookie.name === 'LABSESS');
    const sessionB = cookiesB.find((cookie: { name: string }) => cookie.name === 'LABSESS');
    expect(sessionA).toBeDefined();
    expect(sessionB).toBeUndefined();
    await stack.browser.closeContext(engagement.engagementId, ctxA.id);
    await stack.browser.closeContext(engagement.engagementId, ctxB.id);
  }, 180_000);
});

// Keep the lab app import referenced for clarity.
void startLabApp;
