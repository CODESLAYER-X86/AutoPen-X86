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

describe('projects & authorization (spec §33: unauthorized users cannot access another project)', () => {
  it('creates and lists own projects', async () => {
    const { token } = await registerAndLogin(test.app, 'owner@test.local');
    const create = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(token),
      payload: { name: 'Project One', description: 'first' },
    });
    expect(create.statusCode).toBe(201);
    expect(JSON.parse(create.body).id).toMatch(/^PRJ_/);

    const list = await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(token),
    });
    expect(list.statusCode).toBe(200);
    const body = JSON.parse(list.body);
    expect(body.total).toBe(1);
    expect(body.items[0].name).toBe('Project One');
  });

  it('isolates projects between users (404, not 403 — no existence leak)', async () => {
    const alice = await registerAndLogin(test.app, 'alice@iso.test');
    const bob = await registerAndLogin(test.app, 'bob@iso.test');

    const create = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(alice.token),
      payload: { name: "Alice's project", description: '' },
    });
    const projectId = JSON.parse(create.body).id;

    const bobReads = await test.app.inject({
      method: 'GET',
      url: `/api/projects/${projectId}`,
      headers: authHeaders(bob.token),
    });
    expect(bobReads.statusCode).toBe(404);
    expect(JSON.parse(bobReads.body).error.code).toBe('PROJECT_NOT_FOUND');

    // Bob's project list does not include Alice's project.
    const bobList = await test.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: authHeaders(bob.token),
    });
    expect(JSON.parse(bobList.body).total).toBe(0);
  });

  it('engagements inherit the ownership boundary', async () => {
    const alice = await registerAndLogin(test.app, 'alice-eng@iso.test');
    const mallory = await registerAndLogin(test.app, 'mallory@iso.test');

    const project = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(alice.token),
      payload: { name: 'P', description: '' },
    });
    const projectId = JSON.parse(project.body).id;

    const engagement = await test.app.inject({
      method: 'POST',
      url: '/api/engagements',
      headers: authHeaders(alice.token),
      payload: { project_id: projectId, name: 'E', mode: 'PENTEST' },
    });
    expect(engagement.statusCode).toBe(201);
    const engagementId = JSON.parse(engagement.body).id;

    // Mallory cannot create an engagement in Alice's project.
    const malloryCreate = await test.app.inject({
      method: 'POST',
      url: '/api/engagements',
      headers: authHeaders(mallory.token),
      payload: { project_id: projectId, name: 'Evil', mode: 'CTF' },
    });
    expect(malloryCreate.statusCode).toBe(404);

    // Mallory cannot read or mutate Alice's engagement.
    for (const [method, url] of [
      ['GET', `/api/engagements/${engagementId}`],
      ['PATCH', `/api/engagements/${engagementId}`],
      ['POST', `/api/engagements/${engagementId}/start`],
      ['GET', `/api/engagements/${engagementId}/events`],
      ['GET', `/api/engagements/${engagementId}/targets`],
    ] as const) {
      const response = await test.app.inject({
        method,
        url,
        headers: authHeaders(mallory.token),
        payload: method === 'PATCH' ? { name: 'hijacked' } : undefined,
      });
      expect(response.statusCode).toBe(404);
    }
  });

  it('validates project creation payloads strictly', async () => {
    const { token } = await registerAndLogin(test.app, 'strict@test.local');
    const bad = await test.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: authHeaders(token),
      payload: { name: '', description: 'x', unexpected: true },
    });
    expect(bad.statusCode).toBe(400);
    expect(JSON.parse(bad.body).error.code).toBe('BODY_INVALID');
  });
});
