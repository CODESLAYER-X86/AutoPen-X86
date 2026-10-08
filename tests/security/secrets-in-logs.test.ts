import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authHeaders, createTestApp, registerAndLogin, resetDatabase, type TestApp } from '../integration/helpers.js';

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

describe('secrets never appear in logs (spec §23, §33)', () => {
  it('bearer tokens do not appear in any log line', async () => {
    const { token } = await registerAndLogin(test.app, `logtok-${Date.now()}@test.local`);
    await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(token),
    });
    await test.app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: authHeaders(token),
    });
    const allLogs = test.sink.lines.join('\n');
    expect(allLogs).not.toContain(token);
  });

  it('login credentials do not appear in logs', async () => {
    const email = `logcred-${Date.now()}@test.local`;
    const password = 'VerySecretPassword42';
    await test.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email, name: 'Log Test', password },
    });
    await test.app.inject({ method: 'POST', url: '/api/auth/login', payload: { email, password } });
    const allLogs = test.sink.lines.join('\n');
    expect(allLogs).not.toContain(password);
    // Email is not treated as a secret per policy, but the password must be.
  });

  it('secret material stored via the secret store never reaches logs', async () => {
    const secret = 'SESSIONID=super-secret-cookie-XYZ';
    const reference = await test.app.ctx.secretStore.store(secret);
    expect(reference).toMatch(/^SEC_/);
    // Perform operations so logs accumulate, then scan.
    await test.app.inject({ method: 'GET', url: '/api/meta' });
    const allLogs = test.sink.lines.join('\n');
    expect(allLogs).not.toContain(secret);
  });

  it('audit metadata never contains credential material', async () => {
    const { token } = await registerAndLogin(test.app, `auditsec-${Date.now()}@test.local`);
    const project = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(token),
      payload: { name: 'P', description: '' },
    });
    expect(project.statusCode).toBe(201);
    const rows = await test.pool.query('SELECT metadata FROM audit_log');
    const dump = JSON.stringify(rows.rows);
    expect(dump).not.toContain('password');
    expect(dump).not.toContain('token');
    expect(dump).not.toContain('secret');
  });
});
