/**
 * Part 8 security tests — the production readiness suite (spec Part 8 §111):
 * tenant isolation, credential isolation, honest 501s, forged tokens,
 * emergency stop enforcement, and the backup/restore contract.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, registerAndLogin, resetDatabase, type TestApp } from '../integration/helpers.js';
import { createInternalToken, verifyInternalToken } from '@aegis/hardening';

let app: TestApp;
let tokenA: string;
let tokenB: string;
let headersA: Record<string, string>;
let engagementAId: string;
let engagementBId: string;

beforeAll(async () => {
  app = await createTestApp({ overrides: { FEATURE_HARDENING: 'true' } });
  await resetDatabase(app.pool);
  await app.pool.query(
    `INSERT INTO emergency_stop (id, status) VALUES ('EST_PLATFORM', 'CLEAR') ON CONFLICT (id) DO NOTHING`,
  );
  const userA = await registerAndLogin(app.app, 'p8-sec-a@test.local');
  const userB = await registerAndLogin(app.app, 'p8-sec-b@test.local');
  tokenA = userA.token;
  tokenB = userB.token;
  headersA = { authorization: `Bearer ${tokenA}` };

  for (const [token, name] of [
    [tokenA, 'eng-a'],
    [tokenB, 'eng-b'],
  ] as const) {
    const project = await app.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: { authorization: `Bearer ${token}` },
      payload: { name: `p8-sec-${name}` },
    });
    const engagement = await app.app.inject({
      method: 'POST',
      url: '/api/engagements',
      headers: { authorization: `Bearer ${token}` },
      payload: { project_id: project.json().id, name, mode: 'PENTEST', description: '' },
    });
    if (name === 'eng-a') engagementAId = engagement.json().id;
    else engagementBId = engagement.json().id;
  }
}, 120_000);

afterAll(async () => {
  await app.close();
}, 60_000);

describe('object-level authorization for Part 8 resources (spec Part 8 §8)', () => {
  it('rejects cross-tenant API credential revocation', async () => {
    const created = await app.app.inject({
      method: 'POST',
      url: '/api/api-keys',
      headers: headersA,
      payload: { kind: 'API_KEY', name: 'mine', scopes: ['read'], ttl_hours: 1 },
    });
    const id = created.json().id as string;
    const foreign = await app.app.inject({
      method: 'POST',
      url: `/api/api-keys/${id}/revoke`,
      headers: { authorization: `Bearer ${tokenB}` },
      payload: {},
    });
    expect(foreign.statusCode).toBe(404);

    // Owner can revoke their own.
    const own = await app.app.inject({
      method: 'POST',
      url: `/api/api-keys/${id}/revoke`,
      headers: headersA,
      payload: {},
    });
    expect(own.statusCode).toBe(200);
  });

  it('hides user A security resources from user B (404 ownership checks)', async () => {
    const grants = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementAId}/grants`,
      headers: { authorization: `Bearer ${tokenB}` },
    });
    expect(grants.statusCode).toBe(404);

    const versions = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementAId}/scope-versions`,
      headers: { authorization: `Bearer ${tokenB}` },
    });
    expect(versions.statusCode).toBe(404);
  });

  it('never lists another user API credentials', async () => {
    await app.app.inject({
      method: 'POST',
      url: '/api/api-keys',
      headers: headersA,
      payload: { kind: 'API_KEY', name: 'a-only', scopes: ['read'], ttl_hours: 1 },
    });
    const bList = await app.app.inject({
      method: 'GET',
      url: '/api/api-keys',
      headers: { authorization: `Bearer ${tokenB}` },
    });
    expect(bList.statusCode).toBe(200);
    expect((bList.json().items as unknown[]).length).toBe(0);
  });
});

describe('forged internal service tokens are rejected (spec Part 8 §5)', () => {
  it('rejects tokens signed with a wrong secret across all subjects', () => {
    const { token } = createInternalToken({
      secret: 'attacker-secret-attacker-secret-32',
      subject: 'ORCHESTRATOR',
      engagementId: 'ENG_X',
      capabilities: ['execute'],
      ttlSeconds: 60,
    });
    for (const subject of ['ORCHESTRATOR', 'WORKER', 'ANALYSIS', 'BROWSER', 'KNOWLEDGE'] as const) {
      expect(() =>
        verifyInternalToken(token, { secret: 'platform-secret-platform-secret-32', expectedSubject: subject }),
      ).toThrow();
    }
  });
});

describe('emergency stop is enforced for every tenant (spec Part 8 §89)', () => {
  it('blocks user B target-bound actions while engaged by user A', async () => {
    // Scope for B so the request would otherwise reach the engine.
    await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementBId}/scope`,
      headers: { authorization: `Bearer ${tokenB}` },
      payload: {
        allowed_hosts: ['example.com'],
        allowed_domains: [],
        allowed_ports: [80],
        allowed_schemes: ['http'],
        excluded_hosts: [],
        excluded_paths: [],
        destructive_actions_allowed: false,
      },
    });
    const engage = await app.app.inject({
      method: 'POST',
      url: '/api/security/emergency-stop/engage',
      headers: headersA,
      payload: { reason: 'security test' },
    });
    expect(engage.statusCode).toBe(200);

    const blocked = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementBId}/http/request`,
      headers: { authorization: `Bearer ${tokenB}` },
      payload: { url: 'http://example.com/', method: 'GET' },
    });
    expect(blocked.statusCode).toBe(403);
    expect(blocked.json().error.code).toBe('EMERGENCY_STOP_ENGAGED');

    const release = await app.app.inject({
      method: 'POST',
      url: '/api/security/emergency-stop/release',
      headers: { authorization: `Bearer ${tokenB}` },
      payload: {},
    });
    // Either tenant's authenticated human may release (§89: human control).
    expect(release.statusCode).toBe(200);
    expect(release.json().status).toBe('CLEAR');
  });
});

describe('honest 501 when the hardening engine is disabled (spec Part 8 §67)', () => {
  it('returns 501 for hardening routes with an explicit message', async () => {
    const offline = await createTestApp({ overrides: { FEATURE_HARDENING: 'false' } });
    try {
      const user = await registerAndLogin(offline.app, 'p8-off@test.local');
      const response = await offline.app.inject({
        method: 'GET',
        url: '/api/security/events',
        headers: { authorization: `Bearer ${user.token}` },
      });
      expect(response.statusCode).toBe(501);
      expect(response.json().error.code).toBe('HARDENING_ENGINE_DISABLED');
      // Health + readiness stay public and honest even when disabled.
      const health = await offline.app.inject({ method: 'GET', url: '/api/health' });
      expect(health.statusCode).toBe(200);
      const ready = await offline.app.inject({ method: 'GET', url: '/api/ready' });
      expect(ready.statusCode).toBe(200);
    } finally {
      await offline.close();
    }
  });
});

describe('audit log integrity at the boundary (spec Part 8 §85-§86)', () => {
  it('prevents audit rows from being deleted silently (append-only chain)', async () => {
    // A deletion is detected as a broken chain (prev_hash mismatch).
    const before = await app.app.inject({ method: 'POST', url: '/api/audit-chain/verify', headers: headersA, payload: {} });
    expect(before.json().verified).toBe(true);
    const mid = await app.pool.query<{ id: string }>('SELECT id FROM audit_log ORDER BY chain_seq DESC OFFSET 3 LIMIT 1');
    await app.pool.query('DELETE FROM audit_log WHERE id = $1', [mid.rows[0]!.id]);
    const after = await app.app.inject({ method: 'POST', url: '/api/audit-chain/verify', headers: headersA, payload: {} });
    const body = after.json();
    expect(body.verified).toBe(false);
    expect(body.reason ?? '').toMatch(/prev_hash|content_hash/);
  });
});
