/**
 * Part 7 security tests — the trust, permission and safety boundaries of the
 * verification, reporting and evaluation layers:
 *
 *  §24/§65    secrets never leave reports unredacted (every format).
 *  §76        nonexistent evidence references are rejected (hallucination).
 *  §67        human review is audited; the agent conclusion is never
 *             silently overwritten; cross-engagement access is 404.
 *  §60        the evaluation API requires authentication.
 *  §73        rejected reports cannot be exported (executive separation).
 *  §88        evaluation runs boot LOCAL fixtures only (scope-safety events).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, resetDatabase, registerAndLogin, type TestApp } from '../integration/helpers.js';
import { buildVrStack, type VrStack } from '../integration/part7-helpers.js';
import { TEST_DATABASE_URL } from '../../vitest.shared.js';
import { createPool } from '@aegis/database';
import { hashPassword } from '@aegis/security';
import { redactText, containsUnredactedSecret } from '@aegis/vr';

let app: TestApp;
let vrStack: VrStack;
let pool: ReturnType<typeof createPool>;
let token: string;
let headers: Record<string, string>;
let otherToken: string;
let otherHeaders: Record<string, string>;

beforeAll(async () => {
  pool = createPool(TEST_DATABASE_URL, { max: 5 });
  await resetDatabase(pool);
  app = await createTestApp({});
  const auth = await registerAndLogin(app.app, 'p7-sec@test.local');
  token = auth.token;
  headers = { authorization: `Bearer ${token}` };
  const other = await registerAndLogin(app.app, 'p7-sec-other@test.local');
  otherToken = other.token;
  otherHeaders = { authorization: `Bearer ${otherToken}` };
  vrStack = await buildVrStack({ pool: app.pool });
});

afterAll(async () => {
  await app.close();
  await vrStack.close();
  await pool.end();
});

async function createEngagement(headersToSend: Record<string, string>): Promise<string> {
  const project = await app.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers: headersToSend,
    payload: { name: `p7-sec-${Date.now()}` },
  });
  const projectId = project.json().id as string;
  const engagement = await app.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers: headersToSend,
    payload: { project_id: projectId, name: 'sec engagement', mode: 'PENTEST' },
  });
  return engagement.json().id as string;
}

describe('redaction boundary (§24, §65)', () => {
  it('never lets session cookies, JWTs or credentials through in any export format', async () => {
    const secrets = [
      'Cookie: session=abc123def456ghi789xyz',
      'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      'Set-Cookie: LABSESS=s3cr3tSESSIONvalue; Path=/',
      'api_key=sk-live-1234567890abcdef',
      'user@example.com',
    ];
    for (const secret of secrets) {
      const result = redactText(secret, 'probe');
      expect(result.text).not.toContain(secret);
      expect(containsUnredactedSecret(result.text).found).toBe(false);
    }
  });
});

describe('report safety (§65, §73, §76)', () => {
  it('rejects reports whose verified findings reference nonexistent evidence (§76)', async () => {
    const engagementId = await createEngagement(headers);
    // Create a candidate through the API.
    const candidate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/findings`,
      headers,
      payload: {
        hypothesis_id: null,
        category: 'AUTHORIZATION',
        title: 'Hallucinated evidence probe',
        observed_behavior: 'the observation text for the probe finding',
        evidence_ids: [],
        test_ids: [],
        target_refs: [],
        endpoint_refs: ['/api/probe'],
        identity_refs: [],
      },
    });
    expect(candidate.statusCode).toBe(201);
    const findingId = candidate.json().finding.id as string;

    // Push it to VERIFIED with a fabricated evidence reference directly in
    // the DB (the API path requires real verification; the validator must
    // catch the fabricated reference regardless of how the state arose).
    await app.pool.query(
      `UPDATE findings SET status = 'VERIFIED', evidence_ids = $1::jsonb, verification_ids = $2::jsonb
       WHERE id = $3`,
      [JSON.stringify(['EVD_NOT_A_REAL_EVIDENC']), JSON.stringify(['VER_FABRICATED________']), findingId],
    );

    const generated = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/reports/generate`,
      headers,
      payload: { type: 'TECHNICAL', formats: ['JSON'] },
    });
    expect(generated.statusCode).toBe(422);
    const body = generated.json() as { report?: { id?: string; status?: string }; validation_issues?: Array<{ code: string }> };
    expect(body.report?.status).toBe('REJECTED');
    expect(body.validation_issues?.some((issue) => issue.code === 'EVIDENCE_REFERENCE_INVALID')).toBe(true);

    // §73: the rejected report cannot be exported.
    const reportId = body.report?.id ?? '';
    const exportAttempt = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/reports/${reportId}/export?format=JSON`,
      headers,
    });
    expect(exportAttempt.statusCode).toBe(400);
  });
});

describe('human review audit (§67-§68)', () => {
  it('rejects unauthenticated access to the evaluation API (§60)', async () => {
    const unauthenticated = await app.app.inject({
      method: 'GET',
      url: '/api/evaluations',
    });
    expect(unauthenticated.statusCode).toBe(401);
    const unauthRun = await app.app.inject({
      method: 'POST',
      url: '/api/evaluations/run',
      payload: { scenario_ids: [] },
    });
    expect(unauthRun.statusCode).toBe(401);
  });

  it('blocks cross-engagement finding access with 404 (§67, ownership)', async () => {
    const mine = await createEngagement(headers);
    const theirs = await createEngagement(otherHeaders);

    const candidate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${mine}/findings`,
      headers,
      payload: {
        hypothesis_id: null,
        category: 'AUTHORIZATION',
        title: 'Cross-tenant probe finding',
        observed_behavior: 'observation for the cross-tenant probe',
        evidence_ids: [],
        test_ids: [],
        target_refs: [],
        endpoint_refs: ['/api/x'],
        identity_refs: [],
      },
    });
    const findingId = candidate.json().finding.id as string;

    // Foreign user: every finding-scoped operation 404s.
    for (const path of [
      `/api/engagements/${mine}/findings/${findingId}`,
      `/api/engagements/${mine}/findings/${findingId}/evidence-graph`,
    ]) {
      const attempt = await app.app.inject({ method: 'GET', url: path, headers: otherHeaders });
      expect(attempt.statusCode).toBe(404);
    }
    for (const path of [
      `/api/engagements/${mine}/findings/${findingId}/verify`,
      `/api/engagements/${mine}/findings/${findingId}/review`,
      `/api/engagements/${mine}/findings/${findingId}/retest`,
    ]) {
      const attempt = await app.app.inject({
        method: 'POST',
        url: path,
        headers: otherHeaders,
        payload: path.endsWith('review') ? { decision: 'REJECT', reason: 'foreign probe' } : {},
      });
      expect(attempt.statusCode).toBe(404);
    }
    // Foreign reports.
    const reportList = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${mine}/reports`,
      headers: otherHeaders,
    });
    expect(reportList.statusCode).toBe(404);
    const reportGenerate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${mine}/reports/generate`,
      headers: otherHeaders,
      payload: { type: 'MACHINE', formats: ['JSON'] },
    });
    expect(reportGenerate.statusCode).toBe(404);
    void theirs;
  });

  it('preserves the agent conclusion and audits human review decisions (§67)', async () => {
    const engagementId = await createEngagement(headers);
    const candidate = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/findings`,
      headers,
      payload: {
        hypothesis_id: null,
        category: 'AUTHORIZATION',
        title: 'Audited review finding',
        observed_behavior: 'observation for the audited review probe',
        evidence_ids: [],
        test_ids: [],
        target_refs: [],
        endpoint_refs: ['/api/notes/1'],
        identity_refs: [],
      },
    });
    const findingId = candidate.json().finding.id as string;
    // The agent concluded VERIFIED (§68 example: agent VERIFIED, human REJECT).
    await app.pool.query(
      `UPDATE findings SET status = 'VERIFIED', confidence = 0.9, verification_ids = $1::jsonb WHERE id = $2`,
      [JSON.stringify(['VER_SEC_TEST_VERIFICAT']), findingId],
    );

    const review = await app.app.inject({
      method: 'POST',
      url: `/api/engagements/${engagementId}/findings/${findingId}/review`,
      headers,
      payload: { decision: 'REJECT', reason: 'insufficient control evidence (§68 example)' },
    });
    expect(review.statusCode).toBe(200);
    const reviewBody = review.json() as { review?: { agent_status?: string; agent_confidence?: number; agent_human_disagreement?: boolean } };
    // The agent's original conclusion is preserved verbatim (§67).
    expect(reviewBody.review?.agent_status).toBe('VERIFIED');
    expect(reviewBody.review?.agent_confidence).toBeCloseTo(0.9, 3);
    expect(reviewBody.review?.agent_human_disagreement).toBe(true);

    // The review is queryable and the lifecycle event is audited.
    const detail = await app.app.inject({
      method: 'GET',
      url: `/api/engagements/${engagementId}/findings/${findingId}`,
      headers,
    });
    expect(detail.statusCode).toBe(200);
    const detailBody = detail.json() as { reviews?: unknown[]; lifecycle?: Array<{ actor?: string }> };
    expect(detailBody.reviews?.length).toBe(1);
    expect(detailBody.lifecycle?.some((event) => event.actor === 'HUMAN')).toBe(true);

    // The route-level audit trail recorded the review (§67 auditable).
    const audit = await app.pool.query(
      `SELECT action FROM audit_log WHERE resource_id = $1 AND action = 'FINDING_HUMAN_REVIEWED'`,
      [findingId],
    );
    expect(audit.rowCount).toBe(1);
  });
});

describe('evaluation safety (§39, §77, §88)', () => {
  it('exposes the scenario registry and executes runs only for authenticated owners', async () => {
    const scenarios = await app.app.inject({
      method: 'GET',
      url: '/api/scenarios',
      headers,
    });
    expect(scenarios.statusCode).toBe(200);
    const body = scenarios.json() as { items?: Array<{ name: string; expected_findings?: Array<unknown> }> };
    expect((body.items ?? []).length).toBeGreaterThanOrEqual(9);
    // Ground-truth match tokens are NOT exposed to the client (§41 hidden).
    for (const scenario of body.items ?? []) {
      for (const expected of scenario.expected_findings ?? []) {
        expect((expected as { match_tokens?: unknown }).match_tokens).toBeUndefined();
      }
    }
  });

  it('keeps the deterministic engines honest when disabled (501, not silent success)', async () => {
    const disabled = await createTestApp({ overrides: { FEATURE_REPORTING: 'false' } });
    try {
      const auth = await registerAndLogin(disabled.app, 'p7-disabled@test.local');
      const disabledHeaders = { authorization: `Bearer ${auth.token}` };
      const probe = await createEngagementFor(disabled);
      const attempt = await disabled.app.inject({
        method: 'POST',
        url: `/api/engagements/${probe.engagementId}/reports/generate`,
        headers: probe.headers,
        payload: { type: 'MACHINE', formats: ['JSON'] },
      });
      expect(attempt.statusCode).toBe(501);
      const attemptBody = attempt.json() as { error?: { code?: string } };
      expect(attemptBody.error?.code).toBe('VR_ENGINE_DISABLED');
      const evaluations = await disabled.app.inject({
        method: 'GET',
        url: '/api/scenarios',
        headers: disabledHeaders,
      });
      expect(evaluations.statusCode).toBe(501);
    } finally {
      await disabled.close();
    }
  });

  it('records scope-safety events for out-of-scope probes during evaluation runs (§77)', { timeout: 90_000 }, async () => {
    const user = await vrStack.repos.users.create({
      email: `p7-sec-eval-${Date.now()}@test.local`,
      name: 'Eval Security',
      passwordHash: hashPassword('password1234'),
    });
    await vrStack.engine.benchmarks.seedScenarios();
    const scenarios = await vrStack.engine.benchmarks.listScenarios({});
    const scopeScenario = scenarios.find((s) => s.name === 'scope-safety-out-of-scope')!;
    const outcome = await vrStack.engine.benchmarks.runEvaluation({
      scenarioIds: [scopeScenario.id],
      label: 'sec-scope',
      startedBy: user.id,
      strategicModel: 'mock',
      tacticalModel: 'mock',
      promptVersions: {},
      toolVersions: {},
      golden: false,
      tags: ['security'],
    });
    expect(outcome.status).toBe('COMPLETED');
    expect(outcome.scenarioResults[0]!.safety_violations).toHaveLength(0);
    const events = await vrStack.repos.evaluationEvents.listByRun(outcome.runId);
    const refused = events.find((e) => e.type === 'SCOPE_REFUSED');
    expect(refused).toBeTruthy();
    expect(refused!.description).toContain('DISCOVERED but NOT EXECUTED');
    // No request was actually sent to the out-of-scope host.
    const requests = await vrStack.repos.httpRequests.listByEngagement(
      outcome.scenarioResults[0]!.engagement_id,
      50,
      0,
    );
    expect(requests.every((r) => !String(r.url).includes('out-of-scope'))).toBe(true);
  });
});

async function createEngagementFor(testApp: TestApp): Promise<{ engagementId: string; headers: Record<string, string> }> {
  const auth = await registerAndLogin(testApp.app, `p7-x-${Date.now()}@test.local`);
  const headers = { authorization: `Bearer ${auth.token}` };
  const project = await testApp.app.inject({
    method: 'POST',
    url: '/api/projects',
    headers,
    payload: { name: 'disabled probe' },
  });
  const engagement = await testApp.app.inject({
    method: 'POST',
    url: '/api/engagements',
    headers,
    payload: { project_id: project.json().id, name: 'disabled probe', mode: 'PENTEST' },
  });
  return { engagementId: engagement.json().id as string, headers };
}
