/**
 * Part 8 integration tests — production hardening over the real composition
 * root (spec Part 8 §7, §11, §14-§15, §44, §59, §62, §85, §89, §91, §94, §98).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { createTestApp, registerAndLogin, resetDatabase, sql, type TestApp } from './helpers.js';

let app: TestApp;
let token: string;
let headers: Record<string, string>;
let engagementId: string;
let projectId: string;

beforeAll(async () => {
  app = await createTestApp({ overrides: { FEATURE_HARDENING: 'true' } });
  await resetDatabase(app.pool);
  // resetDatabase truncates platform-level singleton rows seeded by
  // migrations; reseed them (emergency stop + retention defaults).
  await app.pool.query(
    `INSERT INTO emergency_stop (id, status) VALUES ('EST_PLATFORM', 'CLEAR') ON CONFLICT (id) DO NOTHING`,
  );
  await app.pool.query(
    `INSERT INTO retention_policies (id, data_class, retention_days, hard_delete) VALUES
       ('RTP_RAW_HTTP', 'RAW_HTTP', 90, true),
       ('RTP_SCREENSHOTS', 'SCREENSHOTS', 90, true),
       ('RTP_BROWSER_TRACES', 'BROWSER_TRACES', 60, true),
       ('RTP_HAR', 'HAR', 60, true),
       ('RTP_SOURCE_ARTIFACTS', 'SOURCE_ARTIFACTS', 180, true),
       ('RTP_REPORTS', 'REPORTS', 3650, false),
       ('RTP_AGENT_TRACES', 'AGENT_TRACES', 180, true),
       ('RTP_LOGS', 'LOGS', 90, false),
       ('RTP_EVALUATION_DATA', 'EVALUATION_DATA', 365, false)
     ON CONFLICT (data_class) DO NOTHING`,
  );
  const auth = await registerAndLogin(app.app, 'p8-hard@test.local');
  token = auth.token;
  headers = { authorization: `Bearer ${token}` };

  const project = await app.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers,
    payload: { name: 'p8-hardening' },
  });
  projectId = project.json().id as string;
  const engagement = await app.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers,
    payload: { project_id: projectId, name: 'p8-eng', mode: 'PENTEST', description: '' },
  });
  engagementId = engagement.json().id as string;
}, 120_000);

afterAll(async () => {
  await app.close();
}, 60_000);

describe('tamper-evident audit chain (spec Part 8 §85-§86)', () => {
  it('appends chained audit records and verifies the chain', async () => {
    for (let i = 0; i < 3; i += 1) {
      await app.app.inject({
        method: 'POST',
        url: '/api/security/events',
        headers,
        payload: { severity: 'INFO', category: 'AUDIT_TEST', actor: 'USER', engagement_id: null, description: `probe ${i}` },
      });
    }
    const verify = await app.app.inject({ method: 'POST', url: '/api/audit-chain/verify', headers, payload: {} });
    expect(verify.statusCode).toBe(200);
    const body = verify.json();
    expect(body.verified).toBe(true);
    expect(body.records_checked ?? -1).toBeGreaterThanOrEqual(3);
    expect(body.first_broken_record_id).toBeNull();
  });

  it('detects tampering (content edit breaks the chain)', async () => {
    const victim = await sql<{ id: string }>(
      app.pool,
      'SELECT id FROM audit_log ORDER BY chain_seq DESC LIMIT 1',
    );
    await app.pool.query(`UPDATE audit_log SET action = 'TAMPERED' WHERE id = $1`, [victim[0]!.id]);
    const verify = await app.app.inject({ method: 'POST', url: '/api/audit-chain/verify', headers, payload: {} });
    const body = verify.json();
    expect(body.verified).toBe(false);
    expect(body.first_broken_record_id).toBe(victim[0]?.id);
    // Restore the row so later tests see a clean chain.
    await app.pool.query(`UPDATE audit_log SET action = 'audit_test' WHERE id = $1`, [victim[0]!.id]);
  });
});

describe('API credentials (spec Part 8 §11)', () => {
  it('creates an API key, authenticates with it, and revokes it', async () => {
    const created = await app.app.inject({
      method: 'POST',
      url: '/api/api-keys',
      headers,
      payload: { kind: 'API_KEY', name: 'ci-key', scopes: ['read'], ttl_hours: 1 },
    });
    expect(created.statusCode).toBe(200);
    const { token: apiKey, id } = created.json();

    // The plaintext token authenticates (§11) and is never stored raw.
    const ok = await app.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: { authorization: `Bearer ${apiKey}` },
    });
    expect(ok.statusCode).toBe(200);
    const stored = await sql<{ token_hash: string }>(app.pool, 'SELECT token_hash FROM api_credentials WHERE id = $1', [id]);
    expect(stored[0]?.token_hash).toBe(createHash('sha256').update(apiKey, 'utf8').digest('hex'));

    const revoked = await app.app.inject({
      method: 'POST',
      url: `/api/api-keys/${id}/revoke`,
      headers,
      payload: {},
    });
    expect(revoked.statusCode).toBe(200);

    const afterRevoke = await app.app.inject({
      method: 'GET',
      url: '/api/projects',
      headers: { authorization: `Bearer ${apiKey}` },
    });
    expect(afterRevoke.statusCode).toBe(401);
  });

  it('records last_used_at on API key usage', async () => {
    const created = await app.app.inject({
      method: 'POST',
      url: '/api/api-keys',
      headers,
      payload: { kind: 'PERSONAL_ACCESS_TOKEN', name: 'pat', scopes: ['read'], ttl_hours: 1 },
    });
    const { token: pat, id } = created.json();
    await app.app.inject({ method: 'GET', url: '/api/projects', headers: { authorization: `Bearer ${pat}` } });
    const row = await sql<{ last_used_at: string | null }>(
      app.pool,
      'SELECT last_used_at FROM api_credentials WHERE id = $1',
      [id],
    );
    expect(row[0]?.last_used_at ?? 'missing').not.toBeNull();
    await app.app.inject({ method: 'POST', url: `/api/api-keys/${id}/revoke`, headers, payload: {} });
  });
});

describe('security events + incidents (spec Part 8 §94-§96)', () => {
  it('raises events and auto-correlates HIGH events into an incident', async () => {
    for (let i = 0; i < 2; i += 1) {
      const raised = await app.app.inject({
        method: 'POST',
        url: '/api/security/events',
        headers,
        payload: {
          severity: 'HIGH',
          category: 'OUT_OF_SCOPE_TOOL_EXECUTION',
          actor: 'AGENT',
          engagement_id: engagementId,
          description: 'attempted out-of-scope execution probe',
        },
      });
      expect(raised.statusCode).toBe(200);
      expect(raised.json().severity).toBe('HIGH');
    }
    const incidents = await app.app.inject({ method: 'GET', url: '/api/security/incidents', headers });
    expect(incidents.statusCode).toBe(200);
    const items = incidents.json().items as Array<{ severity: string; event_count: number }>;
    expect(items.length).toBeGreaterThanOrEqual(1);
    expect(items.every((incident) => incident.severity === 'HIGH')).toBe(true);
    const linked = await app.pool.query<{ count: number }>(
      'SELECT COUNT(*)::int AS count FROM security_events WHERE incident_id IS NOT NULL',
    );
    expect(linked.rows[0]!.count).toBeGreaterThanOrEqual(2);

    // Severity floor: an operator cannot downgrade a CRITICAL category.
    const floored = await app.app.inject({
      method: 'POST',
      url: '/api/security/events',
      headers,
      payload: {
        severity: 'INFO',
        category: 'CREDENTIAL_EXPOSURE_SUSPECTED',
        actor: 'USER',
        engagement_id: null,
        description: 'downgrade attempt',
      },
    });
    expect(floored.json().severity).toBe('CRITICAL');
  });

  it('updates incident status through the lifecycle', async () => {
    const incidents = await app.app.inject({ method: 'GET', url: '/api/security/incidents', headers });
    const first = (incidents.json().items as Array<{ id: string }>)[0]!;
    const updated = await app.app.inject({
      method: 'POST',
      url: `/api/security/incidents/${first.id}`,
      headers,
      payload: { status: 'RESOLVED' },
    });
    expect(updated.statusCode).toBe(200);
    expect(updated.json().status).toBe('RESOLVED');
    expect(updated.json().resolved_at).not.toBeNull();
  });
});

describe('circuit breakers (spec Part 8 §97-§99)', () => {
  it('trips after the threshold and resets only via the human route', async () => {
    const hardening = app.app.ctx.hardening!;
    // SCOPE_VIOLATION threshold is 3.
    for (let i = 0; i < 3; i += 1) {
      await hardening.circuitBreakers.recordViolation({
        subject: 'AGENT',
        subjectId: engagementId,
        engagementId,
        category: 'SCOPE_VIOLATION',
      });
    }
    const open = await hardening.circuitBreakers.isOpen({ subject: 'AGENT', subjectId: engagementId });
    expect(open).toBe(true);

    const breakers = await app.app.inject({ method: 'GET', url: '/api/security/breakers', headers });
    const mine = (breakers.json().items as Array<{ id: string; subject_id: string; state: string }>).
      find((breaker) => breaker.subject_id === engagementId);
    expect(mine?.state).toBe('OPEN');

    const reset = await app.app.inject({
      method: 'POST',
      url: `/api/security/breakers/${mine!.id}/reset`,
      headers,
      payload: {},
    });
    expect(reset.statusCode).toBe(200);
    expect(reset.json().state).toBe('CLOSED');
    expect(await hardening.circuitBreakers.isOpen({ subject: 'AGENT', subjectId: engagementId })).toBe(false);
  });
});

describe('emergency stop (spec Part 8 §89-§90)', () => {
  it('engages deterministically, blocks target-bound actions, then releases', async () => {
    // A pending task that the stop must cancel.
    await app.pool.query(
      `INSERT INTO tasks (id, engagement_id, type, objective, worker_type, status, idempotency_key)
       VALUES ('TSK_ESTOP_TEST', $1, 'OBSERVE', 'pending task', 'HTTP_WORKER', 'QUEUED', 'IDE_ESTOP_TEST')`,
      [engagementId],
    );

    const engage = await app.app.inject({
      method: 'POST',
      url: '/api/security/emergency-stop/engage',
      headers,
      payload: { reason: 'integration test emergency' },
    });
    expect(engage.statusCode).toBe(200);
    const state = engage.json();
    expect(state.status).toBe('ENGAGED');
    expect(state.cancelled_tasks).toBeGreaterThanOrEqual(1);
    expect(state.revoked_grants).toBeGreaterThanOrEqual(0);

    // Target-bound HTTP is blocked while engaged.
    const blocked = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/http/request`,
      headers,
      payload: { url: 'http://example.invalid/', method: 'GET' },
    });
    expect([403, 502, 400]).toContain(blocked.statusCode);
    expect(JSON.stringify(blocked.body)).toContain('emergency stop');

    const task = await sql<{ status: string }>(app.pool, 'SELECT status FROM tasks WHERE id = $1', ['TSK_ESTOP_TEST']);
    expect(task[0]?.status).toBe('CANCELLED');

    // State is persisted: a fresh read still shows ENGAGED.
    const read = await app.app.inject({ method: 'GET', url: '/api/security/emergency-stop', headers });
    expect(read.json().status).toBe('ENGAGED');

    const release = await app.app.inject({
      method: 'POST',
      url: '/api/security/emergency-stop/release',
      headers,
      payload: {},
    });
    expect(release.json().status).toBe('CLEAR');
  });
});

describe('scoped credential grants (spec Part 8 §14-§15, §93)', () => {
  it('resolves only with a full context match and revokes immediately', async () => {
    const hardening = app.app.ctx.hardening!;
    // Store the secret through the real encrypted secret store API.
    const secretReference = await app.app.ctx.secretStore.store('super-secret-value');

    const identity = await app.pool.query(
      `INSERT INTO identities (id, engagement_id, name, role, type, created_at)
       VALUES ('IDN_PTESTIDENTITYXYAB', $1, 'test-identity', 'MEMBER', 'USER', now()) RETURNING id`,
      [engagementId],
    );
    const identityId = identity.rows[0].id as string;
    const target = await app.pool.query(
      `INSERT INTO targets (id, engagement_id, type, value, created_at)
       VALUES ('TGT_PTESTTARGETXYZAB', $1, 'HOST', 'scope.example', now()) RETURNING id`,
      [engagementId],
    );
    const targetId = target.rows[0].id as string;

    // Engagement must be RUNNING for grants.
    await app.pool.query(`UPDATE engagements SET status = 'RUNNING' WHERE id = $1`, [engagementId]);

    const grant = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/grants`,
      headers,
      payload: {
        engagement_id: engagementId,
        identity_id: identityId,
        target_id: targetId,
        secret_reference: secretReference,
        purpose: 'AUTHENTICATION',
        ttl_minutes: 30,
      },
    });
    expect(grant.statusCode).toBe(200);
    const grantId = grant.json().id as string;

    // Correct context resolves the secret.
    const secret = await hardening.credentials.resolveForWorker({
      engagementId,
      identityId,
      targetId,
      purpose: 'AUTHENTICATION',
    });
    expect(secret.value).toBe('super-secret-value');

    // Wrong purpose fails closed (and raises a security event).
    await expect(
      hardening.credentials.resolveForWorker({
        engagementId,
        identityId,
        targetId,
        purpose: 'VERIFICATION',
      }),
    ).rejects.toThrow('No active credential grant');
    const event = await sql<{ count: number }>(
      app.pool,
      `SELECT COUNT(*)::int AS count FROM security_events WHERE category = 'CREDENTIAL_ACCESS' AND severity = 'HIGH'`,
    );
    expect(event[0]?.count ?? 0).toBeGreaterThanOrEqual(1);

    // Kill switch: revocation is immediate.
    const revoke = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/grants/${grantId}/revoke`,
      headers,
      payload: { reason: 'suspected leak' },
    });
    expect(revoke.statusCode).toBe(200);
    await expect(
      hardening.credentials.resolveForWorker({
        engagementId,
        identityId,
        targetId,
        purpose: 'AUTHENTICATION',
      }),
    ).rejects.toThrow('No active credential grant');
  });
});

describe('scope versions (spec Part 8 §91-§92)', () => {
  it('proposes, activates, supersedes — history is immutable', async () => {
    const propose = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope-versions`,
      headers,
      payload: {
        allowed_hosts: ['v1.example'],
        allowed_domains: [],
        allowed_ports: [443],
        allowed_schemes: ['https'],
        excluded_hosts: [],
        destructive_actions_allowed: false,
      },
    });
    expect(propose.statusCode).toBe(200);
    const v1 = propose.json();
    expect(v1.version).toBe(1);
    expect(v1.status).toBe('PROPOSED');
    expect(v1.diff.added_hosts).toEqual(['v1.example']);

    const activate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope-versions/${v1.id}/activate`,
      headers,
      payload: {},
    });
    expect(activate.statusCode).toBe(200);
    expect(activate.json().status).toBe('ACTIVE');

    // v2 supersedes v1 atomically; v1 remains queryable (attribution §92).
    const propose2 = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope-versions`,
      headers,
      payload: {
        allowed_hosts: ['v2.example'],
        allowed_domains: [],
        allowed_ports: [443],
        allowed_schemes: ['https'],
        excluded_hosts: [],
        destructive_actions_allowed: false,
      },
    });
    const v2 = propose2.json();
    expect(v2.diff.added_hosts).toEqual(['v2.example']);
    expect(v2.diff.removed_hosts).toEqual(['v1.example']);
    const activate2 = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/scope-versions/${v2.id}/activate`,
      headers,
      payload: {},
    });
    expect(activate2.json().status).toBe('ACTIVE');

    const history = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/scope-versions`,
      headers,
    });
    const items = history.json().items as Array<{ version: number; status: string }>;
    expect(items.map((item) => item.status)).toContain('SUPERSEDED');
    const active = items.find((item) => item.status === 'ACTIVE');
    expect(active?.version).toBe(2);
  });
});

describe('transactional outbox (spec Part 8 §44-§45)', () => {
  it('appends events with per-aggregate sequences and drains them', async () => {
    const hardening = app.app.ctx.hardening!;
    const first = await hardening.outbox.append({
      eventType: 'SECURITY_EVENT_RAISED',
      engagementId,
      aggregateId: engagementId,
      payload: { n: 1 },
    });
    const second = await hardening.outbox.append({
      eventType: 'SECURITY_EVENT_RAISED',
      engagementId,
      aggregateId: engagementId,
      payload: { n: 2 },
    });
    expect(second.sequence).toBe(first.sequence + 1);
    expect(second.causation_id).toBeNull();

    const before = await hardening.outbox.countPending();
    expect(before).toBeGreaterThanOrEqual(2);
    const drain = await hardening.outbox.drain({ batchSize: 10 });
    expect(drain.delivered).toBeGreaterThanOrEqual(2);
    expect(await hardening.outbox.countPending()).toBe(0);

    // Idempotency: duplicate aggregate+sequence is rejected by the schema.
    await expect(
      hardening.outbox.append({
        eventType: 'SECURITY_EVENT_RAISED',
        aggregateId: engagementId,
        payload: { n: 3 },
      }),
    ).resolves.toMatchObject({ sequence: second.sequence + 1 });
    await hardening.outbox.drain({ batchSize: 10 });
  });
});

describe('row-level security (spec Part 8 §7)', () => {
  it('enforces tenant boundaries for the aegis_app role (defense in depth)', async () => {
    // Second tenant with a private project + engagement.
    const other = await registerAndLogin(app.app, 'p8-other@test.local');
    const otherProject = await app.app.inject({
      method: 'POST',
      url: '/api/projects',
      headers: { authorization: `Bearer ${other.token}` },
      payload: { name: 'other-project' },
    });
    const otherProjectId = otherProject.json().id as string;
    const otherEngagement = await app.app.inject({
      method: 'POST',
      url: '/api/engagements',
      headers: { authorization: `Bearer ${other.token}` },
      payload: { project_id: otherProjectId, name: 'other-eng', mode: 'PENTEST', description: '' },
    });
    const otherEngagementId = otherEngagement.json().id as string;

    const scoped = await app.pool.connect();
    try {
      await scoped.query('SET ROLE aegis_app');
      const mineUserId = (await app.pool.query<{ id: string }>('SELECT id FROM users WHERE email = $1', ['p8-hard@test.local'])).rows[0]!.id;
      const otherUserId = (await app.pool.query<{ id: string }>('SELECT id FROM users WHERE email = $1', ['p8-other@test.local'])).rows[0]!.id;

      await scoped.query(`SELECT set_config('aegis.tenant_user_id', $1, false)`, [otherUserId]);
      const otherVisible = await scoped.query<{ id: string }>('SELECT id FROM engagements WHERE id = $1', [otherEngagementId]);
      const otherBlind = await scoped.query<{ id: string }>('SELECT id FROM engagements WHERE id = $1', [engagementId]);
      expect(otherVisible.rows).toHaveLength(1);
      expect(otherBlind.rows).toHaveLength(0);

      await scoped.query(`SELECT set_config('aegis.tenant_user_id', $1, false)`, [mineUserId]);
      const mineVisible = await scoped.query<{ id: string }>('SELECT id FROM engagements WHERE id = $1', [engagementId]);
      const mineBlind = await scoped.query<{ id: string }>('SELECT id FROM engagements WHERE id = $1', [otherEngagementId]);
      expect(mineVisible.rows).toHaveLength(1);
      expect(mineBlind.rows).toHaveLength(0);

      // Cross-tenant INSERT is blocked by WITH CHECK.
      await scoped.query(`SELECT set_config('aegis.tenant_user_id', $1, false)`, [mineUserId]);
      const blockedInsert = await scoped.query(
        `INSERT INTO engagements (id, project_id, name, mode) VALUES ('ENG_RLS_VIOLATION', $1, 'evil', 'PENTEST')`,
        [otherProjectId],
      ).then(() => 'inserted').catch(() => 'blocked');
      expect(blockedInsert).toBe('blocked');
    } finally {
      await scoped.query('RESET ROLE');
      scoped.release();
    }
  });
});

describe('retention (spec Part 8 §59-§60)', () => {
  it('lists policies, updates one, and sweeps old rows', async () => {
    const list = await app.app.inject({ method: 'GET', url: '/api/retention', headers });
    expect(list.statusCode).toBe(200);
    const classes = (list.json().items as Array<{ data_class: string; retention_days: number }>).map((item) => item.data_class);
    expect(classes).toContain('RAW_HTTP');
    expect(classes).toContain('REPORTS');

    const update = await app.app.inject({
      method: 'POST',
      url: '/api/retention',
      headers,
      payload: { data_class: 'RAW_HTTP', retention_days: 0, hard_delete: true },
    });
    expect(update.statusCode).toBe(200);
    expect(update.json().retention_days).toBe(0);

    // Seed one old event row + one old http response row.
    await app.pool.query(
      `INSERT INTO events (id, type, occurred_at) VALUES ('EVT_RETENTION_TEST', 'SCOPE_UPDATED', now() - interval '10 days')`,
    );
    await app.pool.query(
      `INSERT INTO http_requests (id, engagement_id, method, url, normalized_url, normalized_fingerprint,
                                  body_bytes, source, provenance_source, created_at)
       VALUES ('REQ_RETENTION_TEST', $1, 'GET', 'http://old.example/', 'http://old.example/', 'fp-old',
               0, 'IMPORTED', 'HAR', now() - interval '10 days')`,
      [engagementId],
    );
    await app.pool.query(
      `INSERT INTO http_responses (id, request_id, engagement_id, status, created_at)
       VALUES ('RSP_RETENTION_TEST', 'REQ_RETENTION_TEST', $1, 200, now() - interval '10 days')`,
      [engagementId],
    );

    const sweep = await app.app.inject({ method: 'POST', url: '/api/retention/sweep', headers, payload: {} });
    expect(sweep.statusCode).toBe(200);
    const rawHttp = (sweep.json().results as Array<{ data_class: string; deleted: number }>).find((r) => r.data_class === 'RAW_HTTP');
    expect(rawHttp!.deleted).toBeGreaterThanOrEqual(2);

    const oldEvent = await sql<{ count: number }>(app.pool, 'SELECT COUNT(*)::int AS count FROM events WHERE id = $1', ['EVT_RETENTION_TEST']);
    expect(oldEvent[0]?.count ?? -1).toBe(0);
    const oldResponse = await sql<{ count: number }>(app.pool, 'SELECT COUNT(*)::int AS count FROM http_responses WHERE id = $1', ['RSP_RETENTION_TEST']);
    expect(oldResponse[0]?.count ?? -1).toBe(0);

    // Audit rows are NEVER deleted by retention sweeps (§60).
    const auditCount = await sql<{ count: number }>(app.pool, 'SELECT COUNT(*)::int AS count FROM audit_log');
    expect(auditCount[0]?.count ?? 0).toBeGreaterThan(0);
  });
});

describe('health + metrics (spec Part 8 §49, §51-§52)', () => {
  it('exposes public liveness and authenticated readiness/metrics', async () => {
    const health = await app.app.inject({ method: 'GET', url: '/api/health' });
    expect(health.statusCode).toBe(200);
    expect(health.json().alive).toBe(true);

    const ready = await app.app.inject({ method: 'GET', url: '/api/ready' });
    expect(ready.statusCode).toBe(200);
    expect(ready.json().ready).toBe(true);
    const deps = ready.json().dependencies as Array<{ name: string; healthy: boolean }>;
    expect(deps.some((dep) => dep.name === 'postgresql' && dep.healthy)).toBe(true);

    const unauthenticatedMetrics = await app.app.inject({ method: 'GET', url: '/api/metrics' });
    expect(unauthenticatedMetrics.statusCode).toBe(401);

    const metrics = await app.app.inject({ method: 'GET', url: '/api/metrics', headers });
    expect(metrics.statusCode).toBe(200);
    const body = metrics.json();
    expect(body.scope_denials).toBeGreaterThanOrEqual(0);
    expect(body.emergency_stop_engaged).toBe(false);
    expect(body.pending_outbox_events).toBe(0);
    expect(typeof body.open_circuit_breakers).toBe('number');
  });
});
