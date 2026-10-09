/**
 * Part 3 API route tests — the HTTP/browser endpoints over the real
 * composition root (feature flags on, tool gateway path, ownership 404s).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startLabApp, type LabApp } from '../fixtures/labApp.js';
import { createTestApp, registerAndLogin, resetDatabase, type TestApp } from './helpers.js';

let app: TestApp;
let lab: LabApp;
let token: string;
let headers: Record<string, string>;
let engagementId: string;

beforeAll(async () => {
  lab = await startLabApp();
  app = await createTestApp({
    overrides: {
      FEATURE_TOOLS_HTTP: 'true',
      FEATURE_TOOLS_BROWSER: 'true',
    },
  });
  await resetDatabase(app.pool);
  const auth = await registerAndLogin(app.app, 'p3-api@test.local');
  token = auth.token;
  headers = { authorization: `Bearer ${token}` };

  // project -> engagement -> scope pointing at the lab app
  const project = await app.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers,
    payload: { name: 'part3-api' },
  });
  if (project.statusCode !== 201) {
    throw new Error(`project create failed: ${project.statusCode} ${project.body}`);
  }
  const projectId = project.json().id as string;
  const engagement = await app.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers,
    payload: { project_id: projectId, name: 'eng', mode: 'PENTEST', description: '' },
  });
  if (engagement.statusCode !== 201) {
    throw new Error(`engagement create failed: ${engagement.statusCode} ${engagement.body}`);
  }
  engagementId = engagement.json().id as string;
  const scopeResponse = await app.app.inject({
    method: 'POST',
    url: `/api/engagements/${engagementId}/scope`,
    headers,
    payload: {
      allowed_hosts: [lab.host],
      allowed_domains: [],
      allowed_ports: [lab.port],
      allowed_schemes: ['http'],
      excluded_hosts: [],
      excluded_paths: [],
      destructive_actions_allowed: false,
    },
  });
  if (scopeResponse.statusCode !== 200 && scopeResponse.statusCode !== 201) {
    throw new Error(`scope update failed: ${scopeResponse.statusCode} ${scopeResponse.body}`);
  }
}, 120_000);

afterAll(async () => {
  await app.close();
  await lab.close();
}, 60_000);

describe('Part 3 API surface (spec §19-§22, §80, §43)', () => {
  it('lists the implemented interaction tools with honest flags', async () => {
    const response = await app.app.inject({ method: 'GET', url: '/api/tools', headers });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    const names = body.items.map((tool: { name: string }) => tool.name);
    expect(names).toContain('http.request');
    expect(names).toContain('http.replay');
    expect(names).toContain('http.mutate');
    expect(names).toContain('browser.navigate');
    expect(names).toContain('browser.snapshot');
    expect(names).toContain('websocket.observe');
    expect(names).toContain('artifact.read');
    expect(names).toContain('har.import');
    const implemented = body.items.filter((tool: { implemented: boolean }) => tool.implemented);
    expect(implemented.length).toBeGreaterThan(20);
  }, 30_000);

  it('meta reports the interaction layer as real', async () => {
    const response = await app.app.inject({ method: 'GET', url: '/api/meta' });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.capabilities.autonomous_tools.http).toBe(true);
    expect(body.capabilities.autonomous_tools.browser).toBe(true);
  }, 30_000);

  it('executes http.request through the API (gateway path)', async () => {
    const response = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/http/request`,
      headers,
      payload: { method: 'GET', url: `${lab.url}/api/status` },
    });
    if (response.statusCode !== 200) {
      throw new Error(`http.request failed: ${response.statusCode} ${response.body}`);
    }
    const body = response.json();
    expect(body.status).toBe(200);
    expect(body.request_id).toMatch(/^REQ_/);
  }, 30_000);

  it('lists recorded requests paginated', async () => {
    const response = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests?limit=10`,
      headers,
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.total).toBeGreaterThanOrEqual(1);
    expect(body.items[0]?.source).toBe('HTTP_WORKER');
  }, 30_000);

  it('fetches one request with its response', async () => {
    const list = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests`,
      headers,
    });
    const requestId = list.json().items[0]?.id as string;
    const response = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests/${requestId}`,
      headers,
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.request?.id).toBe(requestId);
    expect(body.response?.status).toBe(200);
  }, 30_000);

  it('replays a recorded request through the API (§19)', async () => {
    const list = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests`,
      headers,
    });
    const requestId = list.json().items[0]?.id as string;
    const response = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/http/replay`,
      headers,
      payload: { request_id: requestId },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.status).toBe(200);
    expect(body.request_id).not.toBe(requestId);
  }, 30_000);

  it('mutates + executes through the API (§20-§22)', async () => {
    const list = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests`,
      headers,
    });
    const requestId = list.json().items[0]?.id as string;
    const response = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/http/mutate`,
      headers,
      payload: {
        base_request_id: requestId,
        mutations: [{ location: 'query', name: 'trace', operation: 'add', value: 'api' }],
        execute: true,
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.applied).toHaveLength(1);
    expect(body.status).toBe(200);
  }, 30_000);

  it('imports HAR traffic with per-entry scope filtering (§80)', async () => {
    const response = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/http/har-import`,
      headers,
      payload: {
        har: {
          log: {
            entries: [
              { request: { method: 'GET', url: `${lab.url}/api/status` }, response: { status: 200 } },
              { request: { method: 'GET', url: 'http://elsewhere.example.com/x' }, response: { status: 200 } },
            ],
          },
        },
      },
    });
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.total).toBe(2);
    expect(body.imported).toBe(1);
    expect(body.skipped).toBe(1);
  }, 30_000);

  it('opens a browser context, acts, and closes it (§3-§8, §75)', async () => {
    const opened = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/browser/contexts`,
      headers,
      payload: { identity_id: null },
    });
    expect(opened.statusCode).toBe(200);
    const contextId = opened.json().context_id as string;
    expect(contextId).toMatch(/^CTX_/);

    const navigate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/browser/actions`,
      headers,
      payload: { context_id: contextId, page_id: null, action: 'navigate', url: `${lab.url}/login` },
    });
    expect(navigate.statusCode).toBe(200);
    expect(navigate.json().ok).toBe(true);

    const events = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/browser/events?limit=50`,
      headers,
    });
    expect(events.statusCode).toBe(200);
    const eventTypes = events.json().items.map((event: { event_type: string }) => event.event_type);
    expect(eventTypes).toContain('NAVIGATION_COMPLETED');

    const closed = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/browser/contexts/${contextId}/close`,
      headers,
    });
    expect(closed.statusCode).toBe(200);
  }, 120_000);

  it('returns 404 for foreign engagements (ownership)', async () => {
    const response = await app.app.inject({
      method: 'GET',
      url: '/api/engagements/ENG_NOTAREALENGAGEMENT/http/requests',
      headers,
    });
    expect(response.statusCode).toBe(404);
  }, 30_000);

  it('requires authentication', async () => {
    const response = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/http/requests`,
    });
    expect(response.statusCode).toBe(401);
  }, 30_000);
});
