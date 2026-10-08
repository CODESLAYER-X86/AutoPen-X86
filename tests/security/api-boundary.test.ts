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

describe('authentication boundary (spec §33: frontend cannot bypass authorization)', () => {
  it('rejects requests without a token', async () => {
    for (const url of ['/api/projects', '/api/tools', '/api/engagements/ENG_XXX', '/api/auth/me']) {
      const response = await test.app.inject({ method: 'GET', url });
      expect(response.statusCode, url).toBe(401);
      expect(JSON.parse(response.body).error.code).toBe('UNAUTHENTICATED');
    }
  });

  it('rejects malformed authorization headers', async () => {
    for (const authorization of [
      'Basic abcdef',
      'Bearer ',
      'Bearer short',
      `Bearer ${'x'.repeat(600)}`,
      'SomeNonsense',
    ]) {
      const response = await test.app.inject({
        method: 'GET',
        url: '/api/projects',
        headers: { authorization },
      });
      expect(response.statusCode, authorization.slice(0, 20)).toBe(401);
    }
  });

  it('rejects forged tokens (random data does not authenticate)', async () => {
    const forged = 'A'.repeat(64);
    const response = await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(forged),
    });
    expect(response.statusCode).toBe(401);
    expect(JSON.parse(response.body).error.code).toBe('INVALID_TOKEN');
  });

  it('rejects a token whose session was revoked', async () => {
    const { token } = await registerAndLogin(test.app, `revoke-${Date.now()}@test.local`);
    await test.app.inject({ method: 'POST', url: '/api/auth/logout', headers: authHeaders(token) });
    const response = await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(token),
    });
    expect(response.statusCode).toBe(401);
  });

  it('rejects a token that is a valid session for a DIFFERENT kind of secret (hash mismatch)', async () => {
    // A token which is the hash of another token still fails: only exact
    // matches against stored hashes authenticate.
    const { token } = await registerAndLogin(test.app, `hashprobe-${Date.now()}@test.local`);
    const { createHash } = await import('node:crypto');
    const hashedToken = createHash('sha256').update(token).digest('hex');
    const response = await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(hashedToken),
    });
    expect(response.statusCode).toBe(401);
  });
});

describe('request validation & normalisation (spec §27)', () => {
  it('rejects malformed JSON bodies with 400', async () => {
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      headers: { 'content-type': 'application/json' },
      payload: 'this is { not json',
    });
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error.code).toBe('BODY_PARSE_FAILED');
  });

  it('rejects wrong content types', async () => {
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/auth/register',
      headers: { 'content-type': 'text/plain' },
      payload: 'not json at all',
    });
    expect(response.statusCode).toBe(400);
  });

  it('rejects bodies exceeding the configured limit (413)', async () => {
    const { token } = await registerAndLogin(test.app, `big-${Date.now()}@test.local`);
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: { ...authHeaders(token), 'content-type': 'application/json' },
      payload: { name: 'x'.repeat(2 * 1024 * 1024), description: '' },
    });
    expect(response.statusCode).toBe(413);
    expect(JSON.parse(response.body).error.code).toBe('BODY_TOO_LARGE');
  });

  it('rejects schema-invalid payloads with structured issue details', async () => {
    const { token } = await registerAndLogin(test.app, `schema-${Date.now()}@test.local`);
    const response = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(token),
      payload: { description: 12345 },
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe('BODY_INVALID');
    expect(Array.isArray(body.error.details)).toBe(true);
  });

  it('returns normalised 404 for unknown routes', async () => {
    const response = await test.app.inject({ method: 'GET', url: '/api/nonexistent/route' });
    expect(response.statusCode).toBe(404);
    expect(JSON.parse(response.body).error.code).toBe('ROUTE_NOT_FOUND');
  });

  it('every error response carries a request_id for correlation', async () => {
    const response = await test.app.inject({ method: 'GET', url: '/api/projects' });
    expect(JSON.parse(response.body).error.request_id).toMatch(/^REQ_/);
  });
});

describe('security headers (spec §29)', () => {
  it('sets defensive headers on every response', async () => {
    const response = await test.app.inject({ method: 'GET', url: '/api/meta' });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('DENY');
    expect(response.headers['referrer-policy']).toBe('no-referrer');
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['content-security-policy']).toContain('default-src');
    expect(response.headers['x-robots-tag']).toContain('noindex');
  });

  it('errors also carry security headers', async () => {
    const response = await test.app.inject({ method: 'GET', url: '/api/projects' });
    expect(response.headers['x-content-type-options']).toBe('nosniff');
  });
});
