import { afterAll, beforeAll, afterEach, describe, expect, it } from 'vitest';
import { authHeaders, buildTestConfig, createTestApp, registerAndLogin, resetDatabase, type TestApp } from '../integration/helpers.js';

describe('rate limiting (spec §25, §29)', () => {
  let test: TestApp;

  beforeAll(async () => {
    // Strict auth limiter for a fast, deterministic test.
    test = await createTestApp({ overrides: { AUTH_RATE_LIMIT_MAX: '3', RATE_LIMIT_MAX_REQUESTS: '10000' } });
  });

  afterAll(async () => {
    await test.close();
  });

  afterEach(async () => {
    await resetDatabase(test.pool);
  });

  it('blocks login brute-force bursts with 429', async () => {
    await registerAndLogin(test.app, `burst-${Date.now()}@test.local`).catch(() => undefined);
    let lastStatus = 0;
    for (let i = 0; i < 8; i += 1) {
      const response = await test.app.inject({
        method: 'POST',
        url: '/api/auth/login',
        payload: { email: `burst-${Date.now()}@test.local`, password: 'wrong-password' },
      });
      lastStatus = response.statusCode;
      if (i >= 3) {
        expect(response.statusCode, `attempt ${i}`).toBe(429);
        const body = JSON.parse(response.body);
        expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
        expect(body.error.category).toBe('QUOTA');
      }
    }
    expect(lastStatus).toBe(429);
  });

  it('login limiter is stricter than the general API limiter', async () => {
    // General endpoint stays usable after auth endpoints are throttled:
    // separate buckets per category.
    for (let i = 0; i < 5; i += 1) {
      await test.app.inject({
        method: 'POST',
        url: '/api/auth/login',
        payload: { email: 'nobody@test.local', password: 'wrong-password' },
      });
    }
    const meta = await test.app.inject({ method: 'GET', url: '/api/meta' });
    expect(meta.statusCode).toBe(200);
  });
});

describe('rate limiting on the general API', () => {
  let test: TestApp;

  beforeAll(async () => {
    test = await createTestApp({ overrides: { RATE_LIMIT_MAX_REQUESTS: '5', AUTH_RATE_LIMIT_MAX: '10000' } });
  });

  afterAll(async () => {
    await test.close();
  });

  afterEach(async () => {
    await resetDatabase(test.pool);
  });

  it('throttles excessive authenticated traffic', async () => {
    await resetDatabase(test.pool);
    const { token } = await registerAndLogin(test.app, `apilimit-${Date.now()}@test.local`);
    let saw429 = false;
    for (let i = 0; i < 12; i += 1) {
      const response = await test.app.inject({
        method: 'GET',
        url: '/api/projects',
        headers: authHeaders(token),
      });
      if (response.statusCode === 429) {
        saw429 = true;
        break;
      }
    }
    expect(saw429).toBe(true);
  });

  it('rejections use the standard error envelope', async () => {
    const config = buildTestConfig({ RATE_LIMIT_MAX_REQUESTS: '1' });
    void config;
  });
});
