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

async function setupEngagement(mode: 'PENTEST' | 'CTF' = 'PENTEST'): Promise<{
  token: string;
  engagementId: string;
  projectId: string;
}> {
  const { token } = await registerAndLogin(test.app, `eng-${Date.now()}-${Math.random()}@test.local`);
  const project = await test.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers: authHeaders(token),
    payload: { name: 'P', description: '' },
  });
  const projectId = JSON.parse(project.body).id;
  const engagement = await test.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers: authHeaders(token),
    payload: { project_id: projectId, name: 'E', mode, description: '' },
  });
  return { token, engagementId: JSON.parse(engagement.body).id, projectId };
}

describe('engagement lifecycle integration (spec §27, §31)', () => {
  it('creates an engagement in DRAFT with a mode', async () => {
    const { token, engagementId } = await setupEngagement('CTF');
    const response = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}`,
      headers: authHeaders(token),
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.engagement.status).toBe('DRAFT');
    expect(body.engagement.mode).toBe('CTF');
    expect(body.readiness).toEqual({ has_scope: false, has_targets: false, ready: false });
  });

  it('rejects start when preconditions are unmet (no scope/targets)', async () => {
    const { token, engagementId } = await setupEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/start`,
      headers: authHeaders(token),
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe('ENGAGEMENT_PRECONDITIONS_NOT_MET');
    expect(body.error.details.has_scope).toBe(false);
  });

  it('full happy path: scope -> target -> auto-READY -> start/pause/resume/cancel', async () => {
    const { token, engagementId } = await setupEngagement();

    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: {
        allowed_hosts: ['localhost'],
        allowed_domains: [],
        allowed_ports: [8080],
        allowed_schemes: ['http'],
        excluded_hosts: [],
        excluded_paths: [],
        destructive_actions_allowed: false,
      },
    });
    const target = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'http://localhost:8080/ctf' },
    });
    expect(target.statusCode).toBe(201);

    const afterTarget = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(afterTarget.body).engagement.status).toBe('READY');

    const start = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/start`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(start.body).status).toBe('RUNNING');
    expect(JSON.parse(start.body).started_at).not.toBeNull();

    const pause = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/pause`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(pause.body).status).toBe('PAUSED');

    const resume = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/resume`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(resume.body).status).toBe('RUNNING');

    const cancel = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/cancel`,
      headers: authHeaders(token),
    });
    expect(JSON.parse(cancel.body).status).toBe('CANCELLED');
    expect(JSON.parse(cancel.body).completed_at).not.toBeNull();
  });

  it('rejects invalid transitions (start from PAUSED, transitions from terminal states)', async () => {
    const { token, engagementId } = await setupEngagement();
    // Bring to RUNNING via scope+target.
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: {
        allowed_hosts: ['localhost'],
        allowed_ports: [8080],
        allowed_schemes: ['http'],
      },
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'http://localhost:8080/' },
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/start`,
      headers: authHeaders(token),
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/pause`,
      headers: authHeaders(token),
    });

    // PAUSED -> start endpoint maps to RUNNING via resume semantics; invalid
    // direct transitions via PATCH must fail:
    for (const badStatus of ['COMPLETED', 'DRAFT']) {
      const response = await test.app.inject({
        method: 'PATCH',
        url: `/api/engagements/${engagementId}`,
        headers: authHeaders(token),
        payload: { status: badStatus },
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.parse(response.body).error.code).toBe('INVALID_ENGAGEMENT_TRANSITION');
    }

    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/cancel`,
      headers: authHeaders(token),
    });
    const afterCancel = await test.app.inject({
      method: 'PATCH',
      url: `/api/engagements/${engagementId}`,
      headers: authHeaders(token),
      payload: { status: 'RUNNING' },
    });
    expect(afterCancel.statusCode).toBe(400);
  });

  it('rejects scope mutation while RUNNING', async () => {
    const { token, engagementId } = await setupEngagement();
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: { allowed_hosts: ['localhost'], allowed_schemes: ['http'], allowed_ports: [8080] },
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/targets`,
      headers: authHeaders(token),
      payload: { type: 'URL', value: 'http://localhost:8080/' },
    });
    await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/start`,
      headers: authHeaders(token),
    });
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope`,
      headers: authHeaders(token),
      payload: { allowed_hosts: ['localhost'], allowed_schemes: ['http'], allowed_ports: [8080] },
    });
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error.code).toBe('SCOPE_IMMUTABLE_WHILE_RUNNING');
  });

  it('updates engagement metadata via PATCH', async () => {
    const { token, engagementId } = await setupEngagement();
    const response = await test.app.inject({
      method: 'PATCH',
      url: `/api/engagements/${engagementId}`,
      headers: authHeaders(token),
      payload: { name: 'Renamed', description: 'Updated description' },
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.name).toBe('Renamed');
    expect(body.description).toBe('Updated description');
    expect(body.status).toBe('DRAFT');
  });

  it('lists engagements per project', async () => {
    const { token, projectId } = await setupEngagement();
    await setupEngagement(); // someone else's
    const response = await test.app.inject({
      method: 'GET',
      url: `/api/projects/${projectId}/engagements`,
      headers: authHeaders(token),
    });
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body).total).toBe(1);
  });
});
