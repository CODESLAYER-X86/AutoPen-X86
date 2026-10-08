import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ScopeSchema } from '@aegis/contracts';
import { EncryptedFileSecretStore } from '@aegis/security';
import { authHeaders, createTestApp, registerAndLogin, resetDatabase, sql, type TestApp } from './helpers.js';

let test: TestApp;

beforeAll(async () => {
  test = await createTestApp();
});

afterAll(async () => {
  await test.close();
});

beforeEach(async () => {
  await resetDatabase(test.pool);
});

async function setupEngagement(): Promise<{ token: string; engagementId: string }> {
  const { token } = await registerAndLogin(test.app, `idn-${Date.now()}-${Math.random()}@test.local`);
  const project = await test.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers: authHeaders(token),
    payload: { name: 'P', description: '' },
  });
  const engagement = await test.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers: authHeaders(token),
    payload: { project_id: JSON.parse(project.body).id, name: 'E', mode: 'CTF' },
  });
  return { token, engagementId: JSON.parse(engagement.body).id };
}

describe('identities & target sessions integration (spec §13)', () => {
  it('creates identities and lists them', async () => {
    const { token, engagementId } = await setupEngagement();
    for (const identity of [
      { name: 'Anonymous', type: 'ANONYMOUS', role: '' },
      { name: 'Admin', type: 'ADMIN', role: 'administrator' },
      { name: 'Service', type: 'SERVICE', role: 'ci-bot' },
    ]) {
      const response = await test.app.inject({
        method: 'POST',
        url: `/api/engagements/${engagementId}/identities`,
        headers: authHeaders(token),
        payload: identity,
      });
      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.id).toMatch(/^IDN_/);
      expect(body.type).toBe(identity.type);
      expect(body.metadata).toEqual({});
    }
    const list = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/identities`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(list.body).total).toBe(3);
  });

  it('rejects invalid identity types', async () => {
    const { token, engagementId } = await setupEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/identities`,
      headers: authHeaders(token),
      payload: { name: 'X', type: 'SUPERUSER' },
    });
    expect(response.statusCode).toBe(400);
  });

  it('target sessions store only secret references (secure reference chain)', async () => {
    const { token, engagementId } = await setupEngagement();
    const identity = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/identities`,
      headers: authHeaders(token),
      payload: { name: 'User A', type: 'USER', role: 'standard user' },
    });
    const identityId = JSON.parse(identity.body).id;

    // Sessions are created through repositories (API surface arrives with
    // the HTTP worker in Part 3) — proving the secure reference chain.
    const cookieValue = 'SESSIONID=super-secret-cookie-value-9f8e7d6c5b4a';
    const reference = await test.app.ctx.secretStore.store(cookieValue);

    const created = await test.app.ctx.repos.sessions.create({
      identityId,
      type: 'COOKIE',
      secretReference: reference,
      metadata: { cookie_name: 'SESSIONID', secure: true, httponly: true },
      expiresAt: null,
    });
    expect(created.id).toMatch(/^SES_/);
    expect(created.secret_reference).toMatch(/^SEC_/);

    // Database holds the reference, never the credential.
    const rows = await sql<{ secret_reference: string }>(
      test.pool,
      'SELECT secret_reference FROM sessions WHERE id = $1',
      [created.id],
    );
    const dbDump = JSON.stringify(rows);
    expect(dbDump).not.toContain(cookieValue);

    // Reference resolves through the secret store only.
    expect(await test.app.ctx.secretStore.resolve(rows[0]!.secret_reference)).toBe(cookieValue);

    // Session metadata contains non-secret context only.
    expect(created.metadata.cookie_name).toBe('SESSIONID');
    expect(JSON.stringify(created.metadata)).not.toContain(cookieValue);
  });

  it('session records are identity-scoped and typed', async () => {
    const { token, engagementId } = await setupEngagement();
    const identity = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/identities`,
      headers: authHeaders(token),
      payload: { name: 'User B', type: 'USER' },
    });
    const identityId = JSON.parse(identity.body).id;
    const reference = await test.app.ctx.secretStore.store('jwt-token-abcdef.ghijkl.mnopqr');
    const session = await test.app.ctx.repos.sessions.create({
      identityId,
      type: 'JWT',
      secretReference: reference,
      metadata: { token_name: 'id_token' },
    });
    const listed = await test.app.ctx.repos.sessions.listByIdentity(identityId);
    expect(listed).toHaveLength(1);
    expect(listed[0]!.id).toBe(session.id);
    expect(listed[0]!.type).toBe('JWT');
    expect(listed[0]!.status).toBe('ACTIVE');
  });

  it('scope rows round-trip with the contract schema (type fidelity)', async () => {
    const { token, engagementId } = await setupEngagement();
    const save = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: {
        allowed_hosts: ['h1.example'],
        allowed_domains: ['example.com'],
        allowed_ports: [80, 443],
        allowed_schemes: ['https'],
        excluded_hosts: ['x.example.com'],
        excluded_paths: ['/x'],
        rate_limit: 30,
        concurrency_limit: 5,
        destructive_actions_allowed: false,
      },
    });
    expect(save.statusCode).toBe(200);
    const parsed = ScopeSchema.safeParse(JSON.parse(save.body));
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.allowed_ports).toEqual([80, 443]);
      expect(parsed.data.rate_limit).toBe(30);
    }
  });
});

describe('encrypted secret store filesystem (integration)', () => {
  it('writes and reads encrypted secrets from the configured path', async () => {
    const store = new EncryptedFileSecretStore({ filePath: test.config.secretStore.path });
    const reference = await store.store('integration-secret-value');
    expect(await store.resolve(reference)).toBe('integration-secret-value');
  });
});
