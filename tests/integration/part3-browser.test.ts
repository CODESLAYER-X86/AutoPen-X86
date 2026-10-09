/**
 * Part 3 browser integration tests (spec §82.1, §82.3) — REAL Chromium via
 * Playwright against the local lab app (§83). Verifies context isolation,
 * identity isolation, all core actions, network/cookie/storage/download/
 * WebSocket capture, and deterministic cleanup.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateId } from '@aegis/shared';
import { createPool } from '@aegis/database';
import { UsersRepository } from '@aegis/database';
import { buildInteractionStack, gatewayContext, seedEngagement, type InteractionStack } from './part3-helpers.js';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

let stack: InteractionStack;
let engagement: { engagementId: string; identityA: string; identityB: string; anonymous: string };

beforeAll(async () => {
  const pool = createPool(TEST_DATABASE_URL, { max: 4 });
  const users = new UsersRepository(pool);
  const user = await users.create({
    email: `p3-browser-${generateId('USR').slice(4).toLowerCase()}@test.local`,
    name: 'Part3 Browser Test',
    passwordHash: 'not-a-real-hash',
  });
  stack = await buildInteractionStack({ pool, browser: { downloadsEnabled: true } });
  engagement = await seedEngagement(stack, user.id);
}, 120_000);

afterAll(async () => {
  if (stack) {
    await stack.browser.closeEngagement(engagement.engagementId).catch(() => undefined);
    await stack.lab.close().catch(() => undefined);
    await stack.pool.end().catch(() => undefined);
  }
}, 120_000);

describe('browser service lifecycle + isolation (§82.1, §3-§6)', () => {
  it('creates isolated contexts per identity and one for anonymous (§3)', async () => {
    const anonymous = await stack.browser.getContextHandle(engagement.engagementId, null);
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    const ctxB = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityB);
    expect(anonymous.id).not.toBe(ctxA.id);
    expect(ctxA.id).not.toBe(ctxB.id);

    const rows = await stack.repos.browserContexts.listByEngagement(engagement.engagementId);
    expect(rows.length).toBeGreaterThanOrEqual(3);

    // Same identity resolves to the SAME context (identity mapping, §4).
    const ctxAgain = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    expect(ctxAgain.id).toBe(ctxA.id);
  }, 60_000);

  it('performs navigation, fill, click and captures the login workflow (§60)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);

    const navigate = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
      timeout_ms: 15_000,
    }, stack.scope);
    expect(navigate.ok).toBe(true);
    expect(navigate.details.status).toBe(200);

    const snapshot = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    expect(snapshot.ok).toBe(true);
    const counts = (snapshot.details as unknown as { counts: Record<string, number> }).counts;
    expect(counts.forms).toBe(1);
    expect(counts.inputs).toBeGreaterThanOrEqual(2);

    const fillUser = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Username' },
      value: 'usera',
    }, stack.scope);
    expect(fillUser.ok).toBe(true);

    const fillPassword = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Password' },
      value: 'password-a',
    }, stack.scope);
    expect(fillPassword.ok).toBe(true);

    const submit = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'click',
      selector: { strategy: 'role', value: 'button', role: 'button', name: 'Login' },
    }, stack.scope);
    expect(submit.ok).toBe(true);
    // The form POST + navigation settle after the click resolves; the next
    // action boundary drains the capture (§75 flush semantics).
    await new Promise((resolve) => setTimeout(resolve, 800));
    const flush = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    expect(flush.ok).toBe(true);
    const rows = await stack.repos.httpRequests.listByEngagement(engagement.engagementId, 100, 0);
    const loginPost = rows.find(
      (row) => row.source === 'BROWSER' && row.method === 'POST' && String(row.url).includes('/login'),
    );
    expect(loginPost).toBeDefined();
  }, 180_000);

  it('captures cookies and storage with redaction (§23-§24)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    const state = await stack.browser.captureContextState(engagement.engagementId, ctxA.id);
    expect(state.cookies.count).toBeGreaterThanOrEqual(1);
    expect(state.cookies.sensitive).toBeGreaterThanOrEqual(1); // LABSESS is httpOnly
    expect(state.storage.entries).toBeGreaterThanOrEqual(2); // localStorage app + sessionStorage visit

    const cookieRows = await stack.repos.cookies.listByContext(ctxA.id);
    expect(cookieRows.some((row) => row.name === 'LABSESS')).toBe(true);
    // Values are opaque secret references, never stored in the row.
    expect(cookieRows.every((row) => /^COOKIE_REF_[A-Z2-7]+$/.test(String(row.secret_reference)))).toBe(true);

    const storageRows = await stack.repos.storageEntries.listByContext(ctxA.id);
    expect(storageRows.length).toBeGreaterThanOrEqual(2);
  }, 60_000);

  it('isolates cookies and storage between identities (§82.3)', async () => {
    // usera logged in during the workflow test; userb navigates fresh.
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    const ctxB = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityB);

    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxB.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    // Explicit captures for both contexts (self-contained, §82.3).
    await stack.browser.captureContextState(engagement.engagementId, ctxA.id);
    await stack.browser.captureContextState(engagement.engagementId, ctxB.id);

    const cookiesA = await stack.repos.cookies.listByContext(ctxA.id);
    const cookiesB = await stack.repos.cookies.listByContext(ctxB.id);
    const cookieA = cookiesA.find((row) => row.name === 'LABSESS');
    const cookieB = cookiesB.find((row) => row.name === 'LABSESS');
    expect(cookieA).toBeDefined();
    expect(cookieB).toBeUndefined(); // userb never logged in -> no session cookie

    const storageA = await stack.repos.storageEntries.listByContext(ctxA.id);
    const storageB = await stack.repos.storageEntries.listByContext(ctxB.id);
    const tokenA = storageA.find((row) => row.key === 'app');
    const tokenB = storageB.find((row) => row.key === 'app');
    // localStorage "app" was set by page JS on both visits, but the VALUES
    // (timestamps) differ and, critically, rows are per-context:
    expect(tokenA?.context_id).toBe(ctxA.id);
    expect(tokenB?.context_id).toBe(ctxB.id);
    expect(tokenA?.id).not.toBe(tokenB?.id);
  }, 120_000);

  it('captures DOM snapshots with structured content + evidence (§31-§32)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    const result = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    expect(result.ok).toBe(true);
    const details = result.details as unknown as { snapshot_id: string; evidence_id: string; counts: Record<string, number> };
    expect(details.snapshot_id).toMatch(/^DMS_/);
    expect(details.evidence_id).toMatch(/^EVD_/);
    expect(details.counts.links).toBeGreaterThanOrEqual(3);
    expect(details.counts.iframes).toBe(1);

    // Dashboard (authenticated via ctxA cookie) loads an external script (§34).
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/dashboard`,
    }, stack.scope);
    const dash = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    const dashCounts = (dash.details as unknown as { counts: Record<string, number> }).counts;
    expect(dashCounts.scripts).toBeGreaterThanOrEqual(1);

    const rows = await stack.repos.domSnapshots.listByEngagement(engagement.engagementId, 10);
    expect(rows.some((row) => row.id === details.snapshot_id)).toBe(true);
  }, 60_000);

  it('detects DOM changes after actions (§33)', async () => {
    const ctx = await stack.browser.getContextHandle(engagement.engagementId, null);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    const before = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    const beforeId = (before.details as unknown as { snapshot_id: string }).snapshot_id;
    const beforeCounts = (before.details as unknown as { counts: Record<string, number> }).counts;
    expect(beforeCounts.forms).toBe(1);

    // Mutate the DOM: submit the login form — the page navigates to the
    // JSON response, replacing the form document entirely.
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Username' },
      value: 'usera',
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'fill',
      selector: { strategy: 'label', value: 'Password' },
      value: 'password-a',
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctx.id,
      page_id: null,
      action: 'click',
      selector: { strategy: 'role', value: 'button', role: 'button', name: 'Login' },
    }, stack.scope);
    await new Promise((resolve) => setTimeout(resolve, 800));

    const diff = await stack.browser.diffAgainstSnapshot(engagement.engagementId, ctx.id, beforeId);
    expect(diff.removed.length + diff.added.length + diff.changed.length).toBeGreaterThan(0);
    expect(diff.removed.some((entry) => entry.includes('form'))).toBe(true);
  }, 120_000);

  it('captures screenshots as evidence artifacts (§38)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    const result = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'screenshot',
    }, stack.scope);
    expect(result.ok).toBe(true);
    const details = result.details as unknown as { evidence_id: string; sha256: string; byte_size: number };
    expect(details.evidence_id).toMatch(/^EVD_/);
    expect(details.byte_size).toBeGreaterThan(1000);
    expect(details.sha256).toMatch(/^[a-f0-9]{64}$/);
  }, 60_000);

  it('promotes browser network traffic into HTTP records (§14, §62)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    const rows = await stack.repos.httpRequests.listByEngagement(engagement.engagementId, 200, 0);
    const browserRecords = rows.filter((row) => row.source === 'BROWSER' && row.browser_context_id === ctxA.id);
    expect(browserRecords.length).toBeGreaterThanOrEqual(1);
    expect(browserRecords.some((row) => String(row.url).includes('/login'))).toBe(true);

    // Browser event stream persisted (§11).
    const events = await stack.repos.browserEvents.listByEngagement(engagement.engagementId, 500);
    expect(events.some((event) => event.event_type === 'NAVIGATION_COMPLETED')).toBe(true);
    expect(events.some((event) => event.event_type === 'RESPONSE_RECEIVED')).toBe(true);
  }, 60_000);

  it('captures downloads as untrusted evidence with sha256 (§37)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    // Download via <a href> click triggers page download event.
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'click',
      selector: { strategy: 'role', value: 'link', role: 'link', name: 'Download' },
      timeout_ms: 10_000,
    }, stack.scope);
    // Give the async download capture a moment to complete.
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const downloads = await stack.repos.downloads.listByEngagement(engagement.engagementId);
    expect(downloads.length).toBeGreaterThanOrEqual(1);
    const download = downloads[0]!;
    expect(download.filename).toBe('report.bin');
    expect(String(download.sha256)).toMatch(/^[a-f0-9]{64}$/);
    expect(Number(download.size)).toBe(4096);
    expect(String(download.evidence_id)).toMatch(/^EVD_/);
  }, 120_000);

  it('observes WebSocket traffic with directions (§36)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    // Open a page that uses the WebSocket and exchange a message.
    const navigate = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    expect(navigate.ok).toBe(true);
    // Trigger a WS connection inside the page via CDP-free path: the
    // service observes connections opened by page scripts. The lab login
    // page does not open one, so connect programmatically through the
    // context's own page (platform-controlled, in-scope).
    const handle = ctxA;
    const page = [...handle.pages.keys()][0];
    expect(page).toBeDefined();
    await page!.evaluate((url: string) => {
      return new Promise<void>((resolve) => {
        const ws = new WebSocket(url);
        ws.onopen = () => {
          ws.send('hello-from-test');
          setTimeout(() => {
            ws.close();
            resolve();
          }, 300);
        };
        ws.onerror = () => resolve();
      });
    }, `${stack.lab.url.replace('http', 'ws')}/ws`);
    await new Promise((resolve) => setTimeout(resolve, 1200));
    // Force-flush events + ws records via an action boundary.
    await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'snapshot',
    }, stack.scope);
    const connections = await stack.repos.websockets.listConnections(engagement.engagementId);
    expect(connections.length).toBeGreaterThanOrEqual(1);
    const connection = connections[0]!;
    expect(String(connection.url)).toContain('/ws');
    const messages = await stack.repos.websockets.listMessages(connection.id as string, 50);
    expect(messages.length).toBeGreaterThanOrEqual(2); // echo:hello (S->C) + hello (C->S)
    expect(messages.some((m) => m.direction === 'CLIENT_TO_SERVER')).toBe(true);
    expect(messages.some((m) => m.direction === 'SERVER_TO_CLIENT')).toBe(true);
  }, 120_000);

  it('executes browser tools through the gateway with scope enforcement (§69)', async () => {
    const result = await stack.gateway.execute(
      'browser.navigate',
      { context_id: (await stack.browser.getContextHandle(engagement.engagementId, null)).id, action: 'navigate', url: `${stack.lab.url}/api/status` },
      gatewayContext(stack, engagement.engagementId),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const output = result.output as { ok: boolean; http_records: string[] };
      expect(output.ok).toBe(true);
      expect(output.http_records.length).toBeGreaterThan(0);
    }
  }, 60_000);

  it('closes contexts deterministically and records the lifecycle (§5, §75)', async () => {
    const ctxA = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityA);
    const ctxB = await stack.browser.getContextHandle(engagement.engagementId, engagement.identityB);

    await stack.browser.closeContext(engagement.engagementId, ctxB.id);
    const rows = await stack.repos.browserContexts.listByEngagement(engagement.engagementId);
    const closed = rows.find((row) => row.id === ctxB.id);
    expect(closed?.status).toBe('CLOSED');
    // ctxA remains usable (independently disposable, §3).
    const still = await stack.browser.performAction(engagement.engagementId, {
      context_id: ctxA.id,
      page_id: null,
      action: 'navigate',
      url: `${stack.lab.url}/login`,
    }, stack.scope);
    expect(still.ok).toBe(true);

    await stack.browser.closeEngagement(engagement.engagementId);
    const after = await stack.repos.browserContexts.listByEngagement(engagement.engagementId);
    expect(after.filter((row) => row.status === 'CLOSED').length).toBe(after.filter((row) => row.id).length);
  }, 120_000);
});
