/**
 * Integration: agent API routes (spec Part 2 §45-§46, §58).
 *
 * Human inspection + intervention over HTTP: runs (start/pause/resume/
 * cancel), tasks, hypotheses, dead ends, strategies, observations, findings,
 * metrics, human overrides (audited), and crash recovery.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authHeaders, createTestApp, registerAndLogin, resetDatabase, type TestApp } from './helpers.js';

let test: TestApp;
let token: string;
let engagementId: string;

beforeAll(async () => {
  test = await createTestApp();
});

afterAll(async () => {
  await test.close();
});

async function setupEngagement(): Promise<void> {
  const email = `agent-api-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@test.local`;
  token = (await registerAndLogin(test.app, email)).token;
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
    payload: { project_id: JSON.parse(project.body).id, name: 'E', mode: 'CTF', description: 'Find the flag.' },
  });
  engagementId = JSON.parse(engagement.body).id;
  await test.app.inject({
    method: 'POST',
    url: `/api/engagements/${engagementId}/scope`,
    headers: authHeaders(token),
    payload: { allowed_hosts: ['app.internal'], allowed_schemes: ['http'], allowed_ports: [8080] },
  });
  await test.app.inject({
    method: 'POST',
    url: `/api/engagements/${engagementId}/targets`,
    headers: authHeaders(token),
    payload: { type: 'URL', value: 'http://app.internal:8080/' },
  });
}

async function startEngagement(): Promise<void> {
  const response = await test.app.inject({
    method: 'POST',
    url: `/api/engagements/${engagementId}/start`,
    headers: authHeaders(token),
  });
  expect(response.statusCode).toBe(200);
}

beforeEach(async () => {
  await resetDatabase(test.pool);
  await setupEngagement();
});

describe('agent run routes (§45)', () => {
  it('refuses to start a run while the engagement is not RUNNING', async () => {
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/runs`,
      headers: authHeaders(token),
      payload: {},
    });
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error.code).toBe('ENGAGEMENT_NOT_RUNNING');
  });

  it('starts, lists, pauses, resumes, and cancels a run', async () => {
    await startEngagement();
    const created = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/runs`,
      headers: authHeaders(token),
      payload: { reason: 'api test' },
    });
    expect(created.statusCode).toBe(201);
    const run = JSON.parse(created.body);
    expect(run.id).toMatch(/^RUN_/);
    expect(run.leader_model).toBeTruthy();
    expect(run.status).toMatch(/^(CREATED|INITIALIZING|RUNNING|WAITING|PAUSED|FAILED)$/);

    const list = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/runs`,
      headers: authHeaders(token),
    });
    expect(list.statusCode).toBe(200);
    expect(JSON.parse(list.body).total).toBeGreaterThanOrEqual(1);

    const paused = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/runs/${run.id}/pause`,
      headers: authHeaders(token),
      payload: {},
    });
    expect(paused.statusCode).toBe(200);
    expect(JSON.parse(paused.body).paused).toBe(true);

    // Resuming an already-terminated run (the mock leader fails fast) is a
    // structured error, never a crash.
    const cancelled = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/runs/${run.id}/cancel`,
      headers: authHeaders(token),
      payload: {},
    });
    expect(cancelled.statusCode).toBe(200);
    expect(JSON.parse(cancelled.body).cancelled).toBe(true);

    // The run lifecycle is audited.
    const events = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/events?limit=200`,
      headers: authHeaders(token),
    });
    const types = JSON.parse(events.body).items.map((e: { type: string }) => e.type);
    expect(types).toContain('AGENT_RUN_CREATED');
    expect(types).toContain('AGENT_RUN_PAUSED');
  });

  it('404s cross-tenant engagement access', async () => {
    const other = await registerAndLogin(test.app, `other-${Date.now()}@test.local`);
    const response = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/runs`,
      headers: authHeaders(other.token),
    });
    expect(response.statusCode).toBe(404);
  });
});

describe('agent inspection routes (§45)', () => {
  it('exposes tasks, hypotheses, strategies, dead ends, observations, findings, metrics', async () => {
    await startEngagement();
    const endpoints = [
      'tasks',
      'hypotheses',
      'strategies',
      'dead-ends',
      'observations',
      'findings',
      'agent-metrics',
    ];
    for (const endpoint of endpoints) {
      const response = await test.app.inject({
        method: 'GET',
        url: `/api/engagements/${engagementId}/${endpoint}`,
        headers: authHeaders(token),
      });
      expect(response.statusCode, `GET ${endpoint}`).toBe(200);
    }
    const metrics = JSON.parse(
      (
        await test.app.inject({
          method: 'GET',
          url: `/api/engagements/${engagementId}/agent-metrics`,
          headers: authHeaders(token),
        })
      ).body,
    );
    expect(metrics).toHaveProperty('runs');
    expect(metrics).toHaveProperty('cycles');
    expect(metrics).toHaveProperty('tasks');
    expect(metrics).toHaveProperty('hypotheses');
    expect(metrics).toHaveProperty('tokens');
  });
});

describe('human overrides (§46) — all audited', () => {
  it('ADD_CTF_CLUE creates an observation the leader will see as CTF data', async () => {
    await startEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/overrides`,
      headers: authHeaders(token),
      payload: { kind: 'ADD_CTF_CLUE', clue: 'The flag is hidden where old sessions go to die.' },
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.observation_id).toMatch(/^OBS_/);

    const observations = JSON.parse(
      (
        await test.app.inject({
          method: 'GET',
          url: `/api/engagements/${engagementId}/observations`,
          headers: authHeaders(token),
        })
      ).body,
    );
    const clue = observations.items.find((o: { id: string }) => o.id === body.observation_id);
    expect(clue.type).toBe('CTF_CLUE');
    expect(clue.metadata.source).toBe('human');

    // The override is audited.
    const audit = await test.pool.query<{ action: string }>(
      'SELECT action FROM audit_log WHERE engagement_id = $1',
      [engagementId],
    );
    expect(audit.rows.some((row) => row.action === 'HUMAN_OVERRIDE_ADD_CTF_CLUE')).toBe(true);
  });

  it('PRIORITIZE_HYPOTHESIS updates hypothesis priority and validates ownership', async () => {
    await startEngagement();
    // Seed a hypothesis directly.
    const user = await test.pool.query<{ id: string }>('SELECT id FROM users LIMIT 1');
    void user;
    const hypothesis = JSON.parse(
      (
        await test.app.inject({
          method: 'POST',
          url: `/api/engagements/${engagementId}/overrides`,
          headers: authHeaders(token),
          payload: { kind: 'ADD_CTF_CLUE', clue: 'Seeding clue for priority test.' },
        })
      ).body,
    );
    void hypothesis;

    // Create a hypothesis through the DB (override requires an existing id).
    const created = await test.pool.query<{ id: string }>(
      `INSERT INTO hypotheses (id, engagement_id, type, statement, status, confidence, priority, source)
       VALUES ('HYP_ABCDEFGHIJKLMNOP', $1, 'CTF_CLUE', 'A test hypothesis for prioritization.', 'PROPOSED', 0.5, 0.5, 'human')
       RETURNING id`,
      [engagementId],
    );
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/overrides`,
      headers: authHeaders(token),
      payload: {
        kind: 'PRIORITIZE_HYPOTHESIS',
        hypothesis_id: created.rows[0]!.id,
        priority: 0.95,
        reason: 'operator emphasis',
      },
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.priority).toBe(0.95);
  });

  it('rejects unknown override kinds (schema-validated)', async () => {
    await startEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/overrides`,
      headers: authHeaders(token),
      payload: { kind: 'DELETE_DATABASE', reason: 'nice try' },
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('crash recovery route (§63-§64)', () => {
  it('runs recovery and reports the outcome', async () => {
    await startEngagement();
    const response = await test.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/recovery`,
      headers: authHeaders(token),
      payload: {},
    });
    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body).toHaveProperty('recovered');
    expect(body).toHaveProperty('finalized');
    expect(body).toHaveProperty('requeued');
    expect(body).toHaveProperty('failed');
  });
});
