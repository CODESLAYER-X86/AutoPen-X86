/**
 * End-to-end test: real HTTP server (not fastify.inject) + local mock
 * target fixture. Exercises the full stack over the wire, including
 * security headers and JSON responses on a real socket.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { startMockTarget } from '../fixtures/mockTargetServer.js';
import { createTestApp, resetDatabase, type TestApp } from '../integration/helpers.js';

let test: TestApp;
let target: Awaited<ReturnType<typeof startMockTarget>>;
let baseUrl: string;

beforeAll(async () => {
  test = await createTestApp();
  await test.app.listen({ port: 0, host: '127.0.0.1' });
  const address = test.app.server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
  target = await startMockTarget();
});

afterAll(async () => {
  await target.close();
  await test.app.close();
  await test.pool.end();
});

beforeEach(async () => {
  await resetDatabase(test.pool);
});

type Json = Record<string, unknown> | null;

async function api(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<{ status: number; json: Json; headers: Headers }> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    json: text === '' ? null : (JSON.parse(text) as Json),
    headers: response.headers,
  };
}

function jsonField(json: Json, path: string[]): unknown {
  let current: unknown = json;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

describe('e2e: full engagement flow over real HTTP (spec §32, §34)', () => {
  it('register -> project -> engagement -> scope around the mock target -> target -> lifecycle', async () => {
    // Register + login over the wire.
    const email = `e2e-${Date.now()}@test.local`;
    const register = await api('POST', '/api/auth/register', {
      email,
      name: 'E2E Operator',
      password: 'password1234',
    });
    expect(register.status).toBe(201);

    const login = await api('POST', '/api/auth/login', { email, password: 'password1234' });
    expect(login.status).toBe(200);
    const token: string = jsonField(login.json, ['token']) as string;
    expect(typeof token).toBe('string');

    // The login token works on a protected route over the wire.
    const me = await api('GET', '/api/auth/me', undefined, token);
    expect(me.status).toBe(200);
    expect(jsonField(me.json, ['email'])).toBe(email);

    // Project + engagement.
    const project = await api('POST', '/api/projects', { name: 'E2E Project', description: '' }, token);
    expect(project.status).toBe(201);
    const projectId = jsonField(project.json, ['id']) as string;

    const engagement = await api(
      'POST',
      '/api/engagements',
      { project_id: projectId, name: 'E2E Engagement', mode: 'PENTEST', description: 'local lab' },
      token,
    );
    expect(engagement.status).toBe(201);
    expect(jsonField(engagement.json, ['status'])).toBe('DRAFT');
    const engagementId = jsonField(engagement.json, ['id']) as string;

    // Scope built around the LIVE mock target (safe local fixture, §34).
    const targetHost = new URL(target.url).hostname;
    const targetPort = new URL(target.url).port;
    const scope = await api(
      'POST',
      `/api/engagements/${engagementId}/scope`,
      {
        allowed_hosts: [targetHost],
        allowed_domains: [],
        allowed_ports: [Number(targetPort)],
        allowed_schemes: ['http'],
        excluded_hosts: [],
        excluded_paths: [],
        destructive_actions_allowed: false,
      },
      token,
    );
    expect(scope.status).toBe(200);

    // The mock target itself is in scope and accepted.
    const addTarget = await api(
      'POST',
      `/api/engagements/${engagementId}/targets`,
      { type: 'URL', value: `${target.url}/`, label: 'mock lab app' },
      token,
    );
    expect(addTarget.status).toBe(201);

    // An external host is rejected.
    const evil = await api(
      'POST',
      `/api/engagements/${engagementId}/targets`,
      { type: 'URL', value: 'http://example.org/' },
      token,
    );
    expect(evil.status).toBe(422);

    // Auto-READY, then run the lifecycle.
    const started = await api('POST', `/api/engagements/${engagementId}/start`, undefined, token);
    expect(started.status).toBe(200);
    expect(jsonField(started.json, ['status'])).toBe('RUNNING');

    // The mock target really answers (proves the fixture is a live server).
    const targetResponse = await fetch(`${target.url}/api/status`);
    expect(targetResponse.status).toBe(200);
    const targetStatus = (await targetResponse.json()) as { ok: boolean };
    expect(targetStatus.ok).toBe(true);

    // Events + audit are visible over the wire.
    const events = await api('GET', `/api/engagements/${engagementId}/events?limit=50`, undefined, token);
    expect(events.status).toBe(200);
    const items = jsonField(events.json, ['items']) as Array<{ type: string }>;
    const types: string[] = items.map((event) => event.type);
    expect(types).toContain('ENGAGEMENT_CREATED');
    expect(types).toContain('ENGAGEMENT_STARTED');

    const audit = await api('GET', `/api/engagements/${engagementId}/audit?limit=50`, undefined, token);
    expect(audit.status).toBe(200);
    expect((jsonField(audit.json, ['items']) as unknown[]).length).toBeGreaterThan(3);

    // Tools listing is honest about implementation state.
    const tools = await api('GET', '/api/tools', undefined, token);
    expect(tools.status).toBe(200);
    // Part 3: parser.jwt + the interaction toolbox (http/browser/artifact/ws/har).
    const implemented = jsonField(tools.json, ['implemented']);
    expect(implemented).toBeGreaterThanOrEqual(21);
    expect(Number(jsonField(tools.json, ['total']))).toBeGreaterThan(1);
  });

  it('serves security headers and a normalised 404 over the wire', async () => {
    const meta = await fetch(`${baseUrl}/api/meta`);
    expect(meta.status).toBe(200);
    expect(meta.headers.get('x-content-type-options')).toBe('nosniff');
    expect(meta.headers.get('x-frame-options')).toBe('DENY');

    const notFound = await fetch(`${baseUrl}/api/definitely/not/here`);
    expect(notFound.status).toBe(404);
    const body = (await notFound.json()) as { error: { code: string } };
    expect(body.error.code).toBe('ROUTE_NOT_FOUND');
  });
});
