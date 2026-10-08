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

describe('event system & audit trail integration (spec §14, §30)', () => {
  it('records lifecycle events with correlation ids', async () => {
    const { token } = await registerAndLogin(test.app, `evt-${Date.now()}@test.local`);
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
    const engagementId = JSON.parse(engagement.body).id;
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

    const events = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/events?limit=50`,
      headers: authHeaders(token),
    });
    expect(events.statusCode).toBe(200);
    const items = JSON.parse(events.body).items as Array<{
      type: string;
      trace_id: string | null;
      engagement_id: string;
      id: string;
      occurred_at: string;
    }>;
    const types = items.map((item) => item.type);
    expect(types).toContain('ENGAGEMENT_CREATED');
    expect(types).toContain('SCOPE_UPDATED');
    expect(types).toContain('TARGET_ADDED');
    expect(types).toContain('ENGAGEMENT_READY');
    expect(types).toContain('ENGAGEMENT_STARTED');

    // Correlation: every event carries the engagement id, a trace id and
    // the prefixed event id shape.
    for (const item of items) {
      expect(item.engagement_id).toBe(engagementId);
      expect(item.id).toMatch(/^EVT_/);
      expect(item.trace_id).toMatch(/^TRC_/);
      expect(new Date(item.occurred_at).toString()).not.toBe('Invalid Date');
    }
  });

  it('audit trail records security-sensitive operations with actor', async () => {
    const { token, userId } = await registerAndLogin(test.app, `aud-${Date.now()}@test.local`);
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
      payload: { project_id: projectId, name: 'E', mode: 'PENTEST' },
    });
    const engagementId = JSON.parse(engagement.body).id;
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
      url: `/api/engagements/${engagementId}/cancel`,
      headers: authHeaders(token),
    });

    const audit = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/audit?limit=50`,
      headers: authHeaders(token),
    });
    expect(audit.statusCode).toBe(200);
    const entries = JSON.parse(audit.body).items as Array<{
      action: string;
      actor_user_id: string | null;
      resource: string;
      engagement_id: string | null;
      id: string;
    }>;
    const actions = entries.map((entry) => entry.action);
    // Engagement-scoped audit entries (project-level entries are stored
    // with engagement_id NULL and are queried via the actor trail).
    expect(actions).toContain('ENGAGEMENT_CREATED');
    expect(actions).toContain('SCOPE_CHANGED');
    expect(actions).toContain('TARGET_ADDED');
    expect(actions).toContain('ENGAGEMENT_CANCELLED');
    for (const entry of entries) {
      expect(entry.id).toMatch(/^AUD_/);
      expect(entry.actor_user_id).toBe(userId);
      expect(entry.engagement_id).toBe(engagementId);
    }

    // Project-level audit entries exist with the correct actor.
    const projectAudit = await sql<{ action: string; actor_user_id: string | null }>(
      test.pool,
      'SELECT action, actor_user_id FROM audit_log WHERE action = $1',
      ['PROJECT_CREATED'],
    );
    expect(projectAudit).toHaveLength(1);
    expect(projectAudit[0]!.actor_user_id).toBe(userId);
  });

  it('audit rows exist for login failures (security-sensitive)', async () => {
    await test.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: 'ghost@nowhere.local', password: 'wrong-password-xx' },
    });
    const rows = await sql<{ action: string; actor_user_id: string | null }>(
      test.pool,
      'SELECT action, actor_user_id FROM audit_log WHERE action = $1',
      ['LOGIN_FAILED'],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.actor_user_id).toBeNull();
  });

  it('events are engagement-scoped (one engagement never sees another)', async () => {
    const a = await registerAndLogin(test.app, `ea-${Date.now()}@test.local`);
    const b = await registerAndLogin(test.app, `eb-${Date.now()}@test.local`);
    const projectFor = async (token: string) => {
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
        payload: { project_id: JSON.parse(project.body).id, name: 'E', mode: 'CTF' },
      });
      return JSON.parse(engagement.body).id;
    };
    const engagementA = await projectFor(a.token);
    const engagementB = await projectFor(b.token);

    const eventsA = await test.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementA}/events`,
      headers: authHeaders(a.token),
    });
    const items = JSON.parse(eventsA.body).items as Array<{ engagement_id: string }>;
    expect(items.length).toBeGreaterThan(0);
    for (const item of items) expect(item.engagement_id).toBe(engagementA);
    expect(engagementB).not.toBe(engagementA);
  });
});
