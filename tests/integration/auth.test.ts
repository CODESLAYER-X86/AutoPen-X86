import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authHeaders, createTestApp, registerAndLogin, resetDatabase, type TestApp } from './helpers.js';

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

describe('authentication integration (spec §27/§29)', () => {
  it('registers a user and returns the public profile (no password hash)', async () => {
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email: 'alice@test.local', name: 'Alice', password: 'password1234' },
    });
    expect(response.statusCode).toBe(201);
    const body = JSON.parse(response.body);
    expect(body.email).toBe('alice@test.local');
    expect(body.name).toBe('Alice');
    expect(body.id).toMatch(/^USR_/);
    expect(response.body).not.toContain('password');
    expect(response.body).not.toContain('scrypt');
  });

  it('rejects duplicate email registration with a typed error', async () => {
    const payload = { email: 'dup@test.local', name: 'Dup', password: 'password1234' };
    await test.app.inject({ method: 'POST', url: '/api/auth/register', payload });
    const second = await test.app.inject({ method: 'POST', url: '/api/auth/register', payload });
    expect(second.statusCode).toBe(400);
    const body = JSON.parse(second.body);
    expect(body.error.code).toBe('EMAIL_ALREADY_REGISTERED');
  });

  it('rejects weak passwords (policy enforcement)', async () => {
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: { email: 'weak@test.local', name: 'Weak', password: 'short' },
    });
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error.code).toBe('BODY_INVALID');
  });

  it('logs in with valid credentials and returns a session', async () => {
    const { token } = await registerAndLogin(test.app, 'login@test.local');
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('rejects invalid credentials with a generic message (no enumeration)', async () => {
    await registerAndLogin(test.app, 'real@test.local');
    for (const payload of [
      { email: 'real@test.local', password: 'wrong-password' },
      { email: 'ghost@test.local', password: 'whatever-pass' },
    ]) {
      const response = await test.app.inject({ method: 'POST', url: '/api/auth/login', payload });
      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
      expect(body.error.message).toBe('Invalid email or password');
    }
  });

  it('stores only the token hash, never the token itself', async () => {
    const { token, userId } = await registerAndLogin(test.app, 'hashcheck@test.local');
    const rows = await test.pool.query('SELECT token_hash FROM auth_sessions WHERE user_id = $1', [
      userId,
    ]);
    expect(rows.rows).toHaveLength(1);
    const stored = rows.rows[0]!.token_hash as string;
    expect(stored).toMatch(/^[a-f0-9]{64}$/);
    expect(stored).not.toBe(token);
  });

  it('me endpoint returns the authenticated user', async () => {
    const { token } = await registerAndLogin(test.app, 'me@test.local');
    const response = await test.app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: authHeaders(token),
    });
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).email).toBe('me@test.local');
  });

  it('logout revokes the session', async () => {
    const { token } = await registerAndLogin(test.app, 'logout@test.local');
    const logout = await test.app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: authHeaders(token),
    });
    expect(logout.statusCode).toBe(204);
    const after = await test.app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: authHeaders(token),
    });
    expect(after.statusCode).toBe(401);
  });

  it('audit records exist for auth events', async () => {
    await registerAndLogin(test.app, 'audit@test.local');
    const rows = await test.pool.query('SELECT action FROM audit_log ORDER BY created_at');
    const actions = rows.rows.map((row) => row.action);
    expect(actions).toContain('USER_REGISTERED');
    expect(actions).toContain('USER_LOGIN');
  });
});
