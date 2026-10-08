import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
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
  const { token } = await registerAndLogin(test.app, `scope-${Date.now()}-${Math.random()}@test.local`);
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
    payload: { project_id: JSON.parse(project.body).id, name: 'E', mode: 'PENTEST' },
  });
  return { token, engagementId: JSON.parse(engagement.body).id };
}

const validScope = {
  allowed_hosts: ['app.lab.internal', 'localhost'],
  allowed_domains: ['lab.internal'],
  allowed_ports: [8080, 8443],
  allowed_schemes: ['http', 'https'],
  excluded_hosts: ['admin.lab.internal'],
  excluded_paths: ['/admin', '/.git'],
  destructive_actions_allowed: false,
};

describe('scope & target enforcement integration (spec §10, §11, §33)', () => {
  it('saves and reads the scope (upsert semantics)', async () => {
    const { token, engagementId } = await setupEngagement();

    const save = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: validScope,
    });
    expect(save.statusCode).toBe(200);
    const saved = JSON.parse(save.body);
    expect(saved.allowed_hosts).toContain('app.lab.internal');
    expect(saved.excluded_paths).toEqual(['/admin', '/.git']);

    const updated = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: { ...validScope, allowed_hosts: ['other.lab.internal'] },
    });
    expect(updated.statusCode).toBe(200);
    expect(JSON.parse(updated.body).allowed_hosts).toEqual(['other.lab.internal']);

    // Scope rows stay at one per engagement (upsert, no duplicates).
    const rows = await sql<{ n: number }>(test.pool, 'SELECT count(*)::int AS n FROM scope');
    expect(rows[0]!.n).toBe(1);

    const read = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
    });
    expect(read.statusCode).toBe(200);
    expect(JSON.parse(read.body).scope.allowed_hosts).toEqual(['other.lab.internal']);
  });

  it('rejects scope requests without any allowlist entry', async () => {
    const { token, engagementId } = await setupEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: { ...validScope, allowed_hosts: [], allowed_domains: [] },
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects targets before a scope exists', async () => {
    const { token, engagementId } = await setupEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'http://app.lab.internal:8080/' },
    });
    expect(response.statusCode).toBe(422);
    expect(JSON.parse(response.body).error.code).toBe('SCOPE_NOT_CONFIGURED');
  });

  it('accepts in-scope targets and normalises them', async () => {
    const { token, engagementId } = await setupEngagement();
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: validScope,
    });

    const target = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'HTTPS://APP.LAB.INTERNAL:8443/path?x=1', label: 'main app' },
    });
    expect(target.statusCode).toBe(201);
    const body = JSON.parse(target.body);
    expect(body.value).toBe('https://app.lab.internal:8443/path');
    expect(body.label).toBe('main app');

    // Subdomain of allowed domain + allowed port.
    const subdomain = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'DOMAIN', value: 'api.lab.internal' },
    });
    expect(subdomain.statusCode).toBe(201);
  });

  it('rejects a battery of out-of-scope targets deterministically', async () => {
    const { token, engagementId } = await setupEngagement();
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: validScope,
    });

    const cases: Array<{ type: string; value: string; expectedCode: string }> = [
      { type: 'URL', value: 'http://evil.attacker.com:8080/', expectedCode: 'HOST_NOT_ALLOWED' },
      { type: 'URL', value: 'http://app.lab.internal:9090/', expectedCode: 'PORT_NOT_ALLOWED' },
      { type: 'URL', value: 'ftp://app.lab.internal/', expectedCode: 'SCHEME_NOT_ALLOWED' },
      { type: 'URL', value: 'http://admin.lab.internal:8080/', expectedCode: 'HOST_EXCLUDED' },
      { type: 'URL', value: 'http://app.lab.internal:8080/admin/panel', expectedCode: 'PATH_EXCLUDED' },
      { type: 'URL', value: 'http://app.lab.internal:8080/.git/config', expectedCode: 'PATH_EXCLUDED' },
      {
        type: 'URL',
        value: 'http://app.lab.internal@evil.attacker.com:8080/',
        expectedCode: 'USERINFO_NOT_ALLOWED',
      },
      {
        type: 'URL',
        value: 'http://app.lab.internal.evil.attacker.com:8080/',
        expectedCode: 'HOST_NOT_ALLOWED',
      },
      { type: 'DOMAIN', value: 'attacker.net', expectedCode: 'HOST_NOT_ALLOWED' },
      { type: 'IP', value: '10.0.0.1', expectedCode: 'HOST_NOT_ALLOWED' },
    ];

    for (const testCase of cases) {
      const response = await test.app.inject({
        method: 'POST',
        url: `/api/engagements/${engagementId}/targets`,
        headers: authHeaders(token),
        payload: { type: testCase.type, value: testCase.value },
      });
      expect(response.statusCode, `target ${testCase.value}`).toBe(422);
      const body = JSON.parse(response.body);
      expect(body.error.code, `target ${testCase.value}`).toBe('TARGET_OUT_OF_SCOPE');
      expect(
        (body.error.details as { code: string }).code,
        `target ${testCase.value}`,
      ).toBe(testCase.expectedCode);
    }

    // Out-of-scope attempts were audited and evented.
    const rejected = await sql<{ n: number }>(
      test.pool,
      'SELECT count(*)::int AS n FROM audit_log WHERE action = $1',
      ['TARGET_REJECTED'],
    );
    expect(rejected[0]!.n).toBe(cases.length);
  });

  it('out-of-scope targets never reach the database', async () => {
    const { token, engagementId } = await setupEngagement();
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: validScope,
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'http://evil.attacker.com:8080/' },
    });
    const rows = await sql<{ value: string }>(
      test.pool,
      'SELECT value FROM targets WHERE engagement_id = $1',
      [engagementId],
    );
    expect(rows).toHaveLength(0);
  });

  it('dedupes identical targets within an engagement', async () => {
    const { token, engagementId } = await setupEngagement();
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: validScope,
    });
    const payload = { type: 'URL', value: 'http://app.lab.internal:8080/' };
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload,
    });
    const second = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload,
    });
    expect(second.statusCode).toBe(400);
    expect(JSON.parse(second.body).error.code).toBe('TARGET_ALREADY_EXISTS');
    const rows = await sql<{ n: number }>(test.pool, 'SELECT count(*)::int AS n FROM targets');
    expect(rows[0]!.n).toBe(1);
  });
});
