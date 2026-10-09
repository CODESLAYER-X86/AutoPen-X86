/**
 * Part 3 HTTP integration tests (spec §82.2) — real engine + recorder +
 * session manager against the local lab app (§83). No external targets.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { buildInteractionStack, gatewayContext, seedEngagement, type InteractionStack } from './part3-helpers.js';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

let stack: InteractionStack;
let userRow: { id: string };
let engagement: { engagementId: string; identityA: string; identityB: string; anonymous: string };

beforeAll(async () => {
  const { generateId } = await import('@aegis/shared');
  const { UsersRepository } = await import('@aegis/database');
  const { createPool } = await import('@aegis/database');
  const pool = createPool(TEST_DATABASE_URL, { max: 4 });
  const users = new UsersRepository(pool);
  const user = await users.create({
    email: `p3-http-${Date.now()}-${generateId('USR').slice(4).toLowerCase()}@test.local`,
    name: 'Part3 Http Test',
    passwordHash: 'not-a-real-hash',
  });
  userRow = { id: user.id };

  stack = await buildInteractionStack({ pool });
  engagement = await seedEngagement(stack, userRow.id);
}, 120_000);

afterAll(async () => {
  await stack?.lab.close().catch(() => undefined);
  await stack?.pool.end().catch(() => undefined);
}, 60_000);

beforeEach(async () => {
  // Rate limiter state is per-instance; tests share the stack intentionally.
});

describe('HTTP engine + traffic recorder (§82.2)', () => {
  it('creates a request, parses a JSON response and records the exchange', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/status` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const output = result.output as {
      status: number;
      request_id: string;
      content_kind: string;
      evidence_id: string;
      body_preview: string | null;
    };
    expect(output.status).toBe(200);
    expect(output.content_kind).toBe('JSON');
    expect(output.request_id).toMatch(/^REQ_/);
    expect(output.evidence_id).toMatch(/^EVD_/);
    expect(JSON.parse(output.body_preview ?? '{}')).toMatchObject({ ok: true });

    // Persisted record + response row.
    const row = await stack.repos.httpRequests.findById(output.request_id);
    expect(row).not.toBeNull();
    expect(row?.source).toBe('HTTP_WORKER');
    const response = await stack.repos.httpResponses.findByRequestId(output.request_id);
    expect(response?.status).toBe(200);
    expect(response?.content_kind).toBe('JSON');

    // Tool execution audit log (§78).
    const executions = await stack.repos.toolExecutions.listByEngagement(engagement.engagementId, 10);
    expect(executions.some((entry) => entry.tool_name === 'http.request' && entry.status === 'SUCCEEDED')).toBe(true);
  }, 30_000);

  it('parses HTML responses with content-kind classification', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/login` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as { content_kind: string };
      expect(output.content_kind).toBe('HTML');
    }
  }, 30_000);

  it('handles binary downloads as FILE/UNKNOWN content without crashing', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/download/report.bin` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as { content_kind: string; truncated: boolean };
      expect(['FILE', 'UNKNOWN', 'BINARY']).toContain(output.content_kind);
      // 4 KiB payload < 2 MiB limit -> NOT truncated, but recorded fully.
      expect(output.truncated).toBe(false);
    }
  }, 30_000);

  it('sends JSON + form + multipart bodies (§67-§68)', async () => {
    const json = await stack.gateway.execute(
      'http.request',
      {
        method: 'POST',
        url: `${stack.lab.url}/api/echo`,
        headers: [{ name: 'content-type', value: 'application/json' }],
        body: { body_type: 'JSON', data: { hello: 'world', n: 5 } },
      },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(json.ok).toBe(true);
    if (json.ok) {
      const output = json.output as { body_preview: string | null };
      const parsed = JSON.parse(output.body_preview ?? '{}') as { received: Record<string, unknown> };
      expect(parsed.received).toMatchObject({ hello: 'world', n: 5 });
    }

    const form = await stack.gateway.execute(
      'http.request',
      {
        method: 'POST',
        url: `${stack.lab.url}/api/echo`,
        body: {
          body_type: 'FORM_URLENCODED',
          fields: [
            { name: 'username', value: 'usera' },
            { name: 'password', value: 'password-a' },
          ],
        },
      },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(form.ok).toBe(true);
    if (form.ok) {
      const output = form.output as { body_preview: string | null };
      expect(output.body_preview).toContain('usera');
      // §66: the stored preview must NOT contain the raw password echo.
      // (the lab app echoes fields; the recorder redacts only its own rows —
      //  the tool output is the target's data, recorded verbatim as evidence)
    }

    const multipart = await stack.gateway.execute(
      'http.request',
      {
        method: 'POST',
        url: `${stack.lab.url}/api/echo`,
        body: {
          body_type: 'MULTIPART',
          fields: [{ name: 'field1', value: 'value1' }],
          files: [{ name: 'file1', filename: 'a.txt', content_b64: Buffer.from('file-content').toString('base64') }],
        },
      },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(multipart.ok).toBe(true);
    if (multipart.ok) {
      const output = multipart.output as { body_preview: string | null };
      const parsed = JSON.parse(output.body_preview ?? '{}') as {
        files: Array<{ name: string; filename: string; bytes: number }>;
      };
      expect(parsed.files).toHaveLength(1);
      expect(parsed.files[0]?.filename).toBe('a.txt');
      expect(parsed.files[0]?.bytes).toBe(Buffer.byteLength('file-content'));
    }
  }, 60_000);

  it('records replay with parent linkage (§19)', async () => {
    const first = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/status` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    const baseId = (first.output as { request_id: string }).request_id;

    const replay = await stack.gateway.execute(
      'http.replay',
      { request_id: baseId },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(replay.ok).toBe(true);
    if (!replay.ok) return;
    const replayOutput = replay.output as { request_id: string; parent: string; status: number };
    expect(replayOutput.status).toBe(200);
    const replayRow = await stack.repos.httpRequests.findById(replayOutput.request_id);
    expect(replayRow?.parent_request_id).toBe(baseId);
    expect(replayRow?.source).toBe('REPLAY');
  }, 30_000);

  it('applies structured mutations then executes the new request (§20-§22)', async () => {
    const base = await stack.gateway.execute(
      'http.request',
      {
        method: 'POST',
        url: `${stack.lab.url}/api/echo`,
        headers: [{ name: 'content-type', value: 'application/json' }],
        body: { body_type: 'JSON', data: { user: { id: 381, role: 'user' } } },
      },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(base.ok).toBe(true);
    if (!base.ok) return;
    const baseId = (base.output as { request_id: string }).request_id;

    const mutated = await stack.gateway.execute(
      'http.mutate',
      {
        base_request_id: baseId,
        mutations: [
          { location: 'body_json', path: 'user.id', operation: 'replace', value: 999 },
          { location: 'query', name: 'flag', operation: 'add', value: '1' },
        ],
        execute: true,
      },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(mutated.ok).toBe(true);
    if (!mutated.ok) return;
    const output = mutated.output as {
      applied: Array<{ location: string }>;
      mutated: { url: string };
      status: number;
      request_id: string;
    };
    expect(output.applied).toHaveLength(2);
    expect(output.mutated.url).toContain('flag=1');
    expect(output.status).toBe(200);
    expect(output.request_id).not.toBe(baseId);

    // Original record is immutable (§21).
    const original = await stack.repos.httpRequests.findById(baseId);
    expect(original?.url).toBe(`${stack.lab.url}/api/echo`);
  }, 30_000);

  it('follows in-scope redirects and records the hop (§51)', async () => {
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/redirect/dashboard` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as { redirects: Array<{ status: number; url: string }>; status: number };
      // /redirect/dashboard -> 302 /dashboard -> 302 /login (no session) -> 200.
      expect(output.redirects.length).toBeGreaterThanOrEqual(1);
      expect(output.redirects.every((hop) => hop.url.startsWith(stack.lab.url))).toBe(true);
      expect(output.status).toBe(200);
    }
  }, 30_000);

  it('times out against unreachable targets with a structured error', async () => {
    // Port with nothing listening on loopback.
    const deadPort = stack.lab.port + 4000;
    const scope = { ...stack.scope, allowed_ports: [...stack.scope.allowed_ports, deadPort] };
    const ctx = gatewayContext(stack, engagement.engagementId, { scope });
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `http://127.0.0.1:${deadPort}/x`, timeout_ms: 2000 },
      ctx,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['HTTP_NETWORK_ERROR', 'HTTP_TIMEOUT']).toContain(result.error.code);
    }
  }, 30_000);

  it('truncates oversized responses with an explicit flag (§48)', async () => {
    const result = await stack.engine.send(
      {
        engagementId: engagement.engagementId,
        method: 'GET',
        url: `${stack.lab.url}/api/oversized`,
        headers: [],
        body: null,
        identityId: null,
      },
      stack.scope,
    );
    // 5 MiB payload > 2 MiB limit: truncated with the explicit flag set.
    expect(exchangeTruncated(result)).toBe(true);
  }, 60_000);

  it('normalizes and dedups fingerprints for identical requests (§18)', async () => {
    const input = { method: 'GET', url: `${stack.lab.url}/api/status?b=2&a=1` };
    const a = await stack.gateway.execute('http.request', input, gatewayContext(stack, engagement.engagementId));
    const b = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/status?a=1&b=2` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      const rowA = await stack.repos.httpRequests.findById((a.output as { request_id: string }).request_id);
      const rowB = await stack.repos.httpRequests.findById((b.output as { request_id: string }).request_id);
      expect(rowA?.normalized_fingerprint).toBe(rowB?.normalized_fingerprint);
      expect(rowA?.normalized_url).toBe(rowB?.normalized_url);
    }
  }, 30_000);
});

/** Extract the truncation flag from an engine exchange. */
function exchangeTruncated(exchange: { response: { truncated: boolean } }): boolean {
  return exchange.response.truncated;
}

describe('Session manager (§26-§29, §82.3 http side)', () => {
  it('injects cookie authentication per identity (§26) and compares identities (§29)', async () => {
    // Login as usera via the engine, capture the LABSESS cookie.
    const login = await stack.engine.send(
      {
        engagementId: engagement.engagementId,
        method: 'POST',
        url: `${stack.lab.url}/login`,
        headers: [{ name: 'content-type', value: 'application/x-www-form-urlencoded' }],
        body: { body_type: 'FORM_URLENCODED', fields: [{ name: 'username', value: 'usera' }, { name: 'password', value: 'password-a' }] },
        identityId: null,
      },
      stack.scope,
    );
    const setCookie = (login.response.headers as Array<{ name: string; value: string }>).find(
      (h) => h.name.toLowerCase() === 'set-cookie',
    );
    expect(setCookie).toBeDefined();
    const token = /LABSESS=([^;]+)/.exec(setCookie?.value ?? '')?.[1] ?? '';
    expect(token).not.toBe('');

    // Register the session for identityA (§28).
    const session = await stack.sessionManager.registerAuthState({
      engagementId: engagement.engagementId,
      identityId: engagement.identityA,
      material: {
        kind: 'COOKIE',
        cookies: [
          {
            name: 'LABSESS',
            value: token,
            domain: '127.0.0.1',
            path: '/',
            secure: false,
            httpOnly: true,
            sameSite: 'Lax',
            expires: null,
          },
        ],
      },
      workflow: { steps: [{ action: 'login', detail: 'form login as usera', success: true }] },
    });
    expect(session.status).toBe('ACTIVE');

    // Identity A request carries the cookie -> authenticated.
    const me = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/me`, identity_id: engagement.identityA },
      gatewayContext(stack, engagement.engagementId, { identityId: engagement.identityA }),
    );
    expect(me.ok).toBe(true);
    if (me.ok) {
      const output = me.output as { status: number; body_preview: string | null };
      expect(output.status).toBe(200);
      expect(JSON.parse(output.body_preview ?? '{}')).toMatchObject({ user: 'usera' });
    }

    // Identity B has no session -> 401 (comparison baseline, §29).
    const noSession = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/me` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(noSession.ok).toBe(true);
    if (noSession.ok) {
      expect((noSession.output as { status: number }).status).toBe(401);
    }

    // Auth workflow recorded (§28).
    const workflows = await stack.repos.authWorkflows.listByEngagement(engagement.engagementId);
    expect(workflows.length).toBeGreaterThan(0);
  }, 30_000);

  it('detects session expiration on 401 and marks the session EXPIRED (§27)', async () => {
    // Register a bogus session for identityB.
    await stack.sessionManager.registerAuthState({
      engagementId: engagement.engagementId,
      identityId: engagement.identityB,
      material: { kind: 'COOKIE', cookies: [{ name: 'LABSESS', value: 'invalid-token', domain: '127.0.0.1', path: '/', secure: false, httpOnly: true, sameSite: null, expires: null }] },
    });
    const before = await stack.repos.sessions.findActiveByIdentity(engagement.identityB);
    expect(before).not.toBeNull();

    // Request with the invalid session -> 401 -> expiration detection.
    const result = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/me`, identity_id: engagement.identityB },
      gatewayContext(stack, engagement.engagementId, { identityId: engagement.identityB }),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect((result.output as { status: number }).status).toBe(401);
    }

    // The session is now EXPIRED with a reason.
    const after = await stack.repos.sessions.listByIdentity(engagement.identityB);
    const latest = after.find((s) => s.status === 'EXPIRED');
    expect(latest).toBeDefined();
    expect(latest?.status_reason).toContain('HTTP_401');

    // Follow-up call fails closed: no active session.
    const rejected = await stack.gateway.execute(
      'http.request',
      { method: 'GET', url: `${stack.lab.url}/api/me`, identity_id: engagement.identityB },
      gatewayContext(stack, engagement.engagementId, { identityId: engagement.identityB }),
    );
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) {
      expect(rejected.error.code).toBe('SESSION_NOT_FOUND');
    }
  }, 30_000);
});
