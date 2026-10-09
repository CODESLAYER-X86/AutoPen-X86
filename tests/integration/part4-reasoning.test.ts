/**
 * Part 4 integration tests (spec §126-§128) — the deterministic reasoning
 * pipeline over REAL recorded traffic against the local lab app:
 *
 *   HTTP request -> endpoint (canonicalization + dedup, §7-§13)
 *   request      -> parameters (§14-§18)
 *   login        -> identity/session + authentication boundary (§20-§22)
 *   identity A/B -> differential analysis (§24-§28)
 *   workflow     -> state graph (§30-§35)
 *   observation  -> security signal (§42-§43)
 *   signal       -> hypothesis candidates with competitors (§44-§47)
 *   hypothesis   -> candidate tests (§48-§50, §118)
 *   verification -> skeptical verdict + dead end (§70-§75)
 *   idempotency  -> re-ingestion produces no duplicates (§111)
 *   leader projection (§120) + event-driven ingestion (§109)
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateId } from '@aegis/shared';
import { createPool, UsersRepository } from '@aegis/database';
import { buildReasoningStack, getAs, loginSession, postAs, settle, type ReasoningStack } from './part4-helpers.js';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

let stack: ReasoningStack;
let userRow: { id: string };
let engagement: { engagementId: string; identityA: string; identityB: string; anonymous: string };
let noteRequestA: string;
let noteRequestB: string;
let noteRequestAnonymous: string;

beforeAll(async () => {
  const pool = createPool(TEST_DATABASE_URL, { max: 4 });
  const users = new UsersRepository(pool);
  const user = await users.create({
    email: `p4-reasoning-${Date.now()}-${generateId('USR').slice(4).toLowerCase()}@test.local`,
    name: 'Part4 Reasoning Test',
    passwordHash: 'not-a-real-hash',
  });
  userRow = { id: user.id };

  stack = await buildReasoningStack({ pool });
  engagement = await (await import('./part3-helpers.js')).seedEngagement(stack.interaction, userRow.id);

  // The §128 end-to-end observation sequence: login, object endpoint,
  // second identity, differing authorization behavior.
  await loginSession(stack, engagement.engagementId, engagement.identityA, 'usera', 'password-a');
  await loginSession(stack, engagement.engagementId, engagement.identityB, 'userb', 'password-b');

  // Fixture A (broken ownership): note 7 is usera's private note.
  const noteA = await getAs(stack, engagement.engagementId, engagement.identityA, '/api/notes/7');
  expect(noteA.status).toBe(200);
  noteRequestA = noteA.requestId;
  const noteB = await getAs(stack, engagement.engagementId, engagement.identityB, '/api/notes/7');
  expect(noteB.status).toBe(200);
  noteRequestB = noteB.requestId;
  // Anonymous access attempt (the §47 public-object discriminator).
  const noteAnon = await getAs(stack, engagement.engagementId, null, '/api/notes/7');
  expect(noteAnon.status).toBe(401);
  noteRequestAnonymous = noteAnon.requestId; // retained: §47 anonymous-replay baseline

  // Fixture A (enforced ownership, negative control): order 1 is usera's.
  await getAs(stack, engagement.engagementId, engagement.identityA, '/api/orders/1');
  await getAs(stack, engagement.engagementId, engagement.identityA, '/api/orders/1'); // reproduction
  await getAs(stack, engagement.engagementId, engagement.identityB, '/api/orders/1'); // 403

  // Fixture B (workflow): register -> verify -> pay -> confirm as usera.
  await postAs(stack, engagement.engagementId, engagement.identityA, '/api/workflow/register');
  await postAs(stack, engagement.engagementId, engagement.identityA, '/api/workflow/verify');
  await postAs(stack, engagement.engagementId, engagement.identityA, '/api/workflow/pay');
  await postAs(stack, engagement.engagementId, engagement.identityA, '/api/workflow/confirm');

  // Fixture C (dynamic API): pagination + volatile timestamps.
  await getAs(stack, engagement.engagementId, null, '/api/items?page=1');
  await getAs(stack, engagement.engagementId, null, '/api/items?page=2');

  // Event-driven ingestion (§109) processes traffic as it lands; the
  // explicit backfill below completes workflows + signal refresh.
  await settle(400);
  await stack.reasoning.ingest(engagement.engagementId);
  await settle(200);
}, 180_000);

afterAll(async () => {
  await stack?.close().catch(() => undefined);
}, 60_000);

// ---------------------------------------------------------------------------
// §126: browser/HTTP observations -> attack surface
// ---------------------------------------------------------------------------

describe('observation ingestion -> attack surface (§7-§13, §109-§110)', () => {
  it('discovers endpoints and deduplicates identifier paths into canonical form', async () => {
    const endpoints = await stack.repos.endpoints.listByEngagement(engagement.engagementId, { limit: 200 });
    expect(endpoints.length).toBeGreaterThan(4);

    // /api/orders/1 and /api/orders/2-observed URLs collapse to one record
    const orders = endpoints.find((endpoint) => endpoint.canonical_path === '/api/orders/{param}');
    expect(orders).toBeDefined();
    // the concrete URLs are recorded as observations on the canonical record
    expect(orders!.observed_urls.some((url) => url.endsWith('/api/orders/1'))).toBe(true);
    expect(orders!.observation_count).toBeGreaterThanOrEqual(2);
    expect(orders!.methods.some((entry) => entry.method === 'GET')).toBe(true);

    // notes + workflow + items endpoints discovered
    expect(endpoints.some((endpoint) => endpoint.canonical_path === '/api/notes/{param}')).toBe(true);
    expect(endpoints.some((endpoint) => endpoint.canonical_path === '/api/workflow/confirm')).toBe(true);
    expect(endpoints.some((endpoint) => endpoint.canonical_path === '/api/items')).toBe(true);

    // discovery source + confidence are recorded honestly (§12-§13)
    expect(orders!.discovery_source).toBeTruthy();
    expect(orders!.confidence_category).toBe('OBSERVED');
  });

  it('extracts parameters with locations and characteristics (§14-§17)', async () => {
    const parameters = await stack.repos.parameters.listByEngagement(engagement.engagementId, 500);
    expect(parameters.length).toBeGreaterThanOrEqual(3);

    const page = parameters.find((parameter) => parameter.name === 'page');
    expect(page?.location).toBe('QUERY');
    expect(page?.example_values).toContain('2');

    // query-string requests produce non-sensitive scalar parameters
    const items = parameters.filter((parameter) => parameter.endpoint_id !== null);
    expect(items.length).toBeGreaterThan(0);

    // resource families (§86)
    const endpoints = await stack.repos.endpoints.listByEngagement(engagement.engagementId, { limit: 200 });
    const notes = endpoints.find((endpoint) => endpoint.canonical_path === '/api/notes/{param}');
    expect(notes?.resource_family).toBe('/api/notes');
  });

  it('records the authorization matrix with identities and object refs (§23, §98)', async () => {
    const matrix = await stack.repos.authzMatrix.listByEngagement(engagement.engagementId, 500);
    expect(matrix.length).toBeGreaterThan(3);

    const notesMatrix = matrix.filter((entry) => entry.outcome === 'ALLOWED' || entry.outcome === 'DENIED');
    // notes:7 — usera ALLOWED, userb ALLOWED (broken), anonymous DENIED
    const noteCells = matrix.filter((entry) => entry.object_ref === 'note:7');
    const allowedIdentities = noteCells.filter((entry) => entry.outcome === 'ALLOWED').map((entry) => entry.identity_id);
    expect(allowedIdentities).toContain(engagement.identityA);
    expect(allowedIdentities).toContain(engagement.identityB);
    expect(noteCells.some((entry) => entry.identity_id === null && entry.outcome === 'DENIED')).toBe(true);

    // orders:1 — usera ALLOWED, userb DENIED (enforced control)
    const orderCells = matrix.filter((entry) => entry.object_ref === 'order:1');
    expect(orderCells.some((entry) => entry.identity_id === engagement.identityA && entry.outcome === 'ALLOWED')).toBe(true);
    expect(orderCells.some((entry) => entry.identity_id === engagement.identityB && entry.outcome === 'DENIED')).toBe(true);
    void notesMatrix;
  });

  it('maps the authentication surface and boundaries (§21-§22)', async () => {
    // Endpoints reached by authenticated identities are marked (§11)
    const endpoints = await stack.repos.endpoints.listByEngagement(engagement.engagementId, { limit: 200 });
    const notes = endpoints.find((endpoint) => endpoint.canonical_path === '/api/notes/{param}');
    expect(notes?.authentication_observed).toBe(true);
    expect(notes?.identities_observed.length).toBeGreaterThanOrEqual(2);

    // The login flow is recorded as an auth workflow + boundary signal (§21-§22)
    const workflows = await stack.repos.authWorkflows.listByEngagement(engagement.engagementId);
    expect(workflows.length).toBeGreaterThanOrEqual(2); // usera + userb logins

    const signals = await stack.repos.securitySignals.listByEngagement(engagement.engagementId, { limit: 300 });
    expect(signals.some((signal) => signal.signal_type === 'AUTH_STATE_CHANGE')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §126: workflow events -> state graph (§30-§35)
// ---------------------------------------------------------------------------

describe('workflow reconstruction (§30-§35)', () => {
  it('reconstructs the candidate workflow with states and transitions', async () => {
    const workflows = await stack.repos.workflows.listByEngagement(engagement.engagementId);
    expect(workflows.length).toBeGreaterThan(0);
    const workflow = workflows[0]!;
    expect(workflow.state_count).toBeGreaterThanOrEqual(3);
    expect(workflow.transition_count).toBeGreaterThanOrEqual(2);

    const states = await stack.repos.workflowStates.listByWorkflow(workflow.id);
    const stateNames = states.map((state) => state.name);
    expect(stateNames).toContain('REGISTRATION');
    expect(stateNames).toContain('VERIFICATION');
    expect(stateNames).toContain('CONFIRMATION');
    // states record HOW they were detected (§31 confidence)
    for (const state of states) {
      expect(state.observed).toBe(true);
      expect(state.confidence).toBeGreaterThan(0);
    }

    const transitions = await stack.repos.workflowTransitions.listByWorkflow(workflow.id);
    for (const transition of transitions) {
      expect(transition.trigger_summary).toMatch(/^(GET|POST) /);
      expect(transition.fingerprint.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// §126: observation -> signal -> hypothesis -> test candidates
// ---------------------------------------------------------------------------

describe('signals and hypotheses (§42-§47, §118)', () => {
  it('generates CROSS_IDENTITY_OBJECT_REFERENCE for the broken note endpoint', async () => {
    const signals = await stack.repos.securitySignals.listByEngagement(engagement.engagementId, { limit: 200 });
    expect(signals.length).toBeGreaterThan(0);

    const crossRef = signals.find((signal) => signal.signal_type === 'CROSS_IDENTITY_OBJECT_REFERENCE');
    expect(crossRef).toBeDefined();
    expect(crossRef!.object_ref).toBe('note:7');
    expect(crossRef!.identity_ids).toContain(engagement.identityA);
    expect(crossRef!.identity_ids).toContain(engagement.identityB);
    expect(crossRef!.confidence).toBeGreaterThan(0.5);
    // signals are NOT conclusions (§42)
    expect(crossRef!.summary).not.toMatch(/vulnerab/i);
  });

  it('generates CROSS_IDENTITY_DIFFERENCE for the enforced order endpoint', async () => {
    const signals = await stack.repos.securitySignals.listByEngagement(engagement.engagementId, { limit: 200 });
    const endpoints = await stack.repos.endpoints.listByEngagement(engagement.engagementId, { limit: 200 });
    const orders = endpoints.find((endpoint) => endpoint.canonical_path === '/api/orders/{param}')!;
    const difference = signals.find(
      (signal) => signal.signal_type === 'CROSS_IDENTITY_DIFFERENCE' && signal.endpoint_id === orders.id,
    );
    expect(difference).toBeDefined();
  });

  it('produces hypothesis candidates with COMPETING interpretations (§44-§45)', async () => {
    const groups = await stack.reasoning.hypothesisCandidates(engagement.engagementId);
    expect(groups.length).toBeGreaterThan(0);

    const group = groups.find((candidateGroup) => candidateGroup.signalType === 'CROSS_IDENTITY_OBJECT_REFERENCE');
    expect(group).toBeDefined();
    // primary + at least 2 competitors (public / shared / cache, §45)
    expect(group!.competitors.length).toBeGreaterThanOrEqual(2);
    // each candidate lists required evidence before promotion (§46)
    expect(group!.primary.required_evidence.length).toBeGreaterThan(0);
    // distinguishing tests are specified (§47)
    expect(group!.distinguishingTests.length).toBeGreaterThan(0);
    // statements mention the object/endpoint, bounded and structured
    expect(group!.primary.statement).toContain('note:7');
  });

  it('plans deterministic test candidates with preconditions (§48-§50, §118)', async () => {
    // Create a real hypothesis first (the leader's job in production).
    const hypothesis = await stack.repos.hypotheses.create({
      engagementId: engagement.engagementId,
      type: 'AUTHORIZATION',
      statement: 'Endpoint /api/notes/{id} may not enforce object-level ownership (note:7 accessible to userb)',
      status: 'ACTIVE',
      confidence: 0.55,
      priority: 0.8,
      source: 'system',
      parentHypothesisId: null,
    });

    const plan = await stack.reasoning.testCandidates(engagement.engagementId);
    expect(plan.items.length).toBeGreaterThan(0);
    for (const candidate of plan.items) {
      expect(candidate.fingerprint).toMatch(/^[a-f0-9]{40}$/);
      expect(candidate.estimated_cost).toBeGreaterThanOrEqual(1);
      expect(candidate.expected_information_gain).toBeGreaterThanOrEqual(0);
      // preconditions are explicit (§49)
      expect(candidate.preconditions).toHaveProperty('scope_ok');
      expect(candidate.preconditions).toHaveProperty('duplicate_absent');
    }
    // identity comparison planned against the notes hypothesis (§61)
    const comparison = plan.items.find(
      (candidate) => candidate.test_type === 'IDENTITY_COMPARISON' && candidate.hypothesis_id === hypothesis.id,
    );
    expect(comparison).toBeDefined();
    expect(comparison!.baseline_identity).not.toBeNull();
    expect(comparison!.candidate_identity).not.toBeNull();
    // anonymous replays genuinely separate the default competing pair (§47)
    const anonymous = plan.items.find(
      (candidate) => candidate.test_type === 'ANONYMOUS_ACCESS' && candidate.hypothesis_id === hypothesis.id,
    );
    expect(anonymous).toBeDefined();
    expect(anonymous!.expected_information_gain).toBeGreaterThan(0);

    // re-planning is deterministic: the same fingerprints reappear; the
    // duplicate precondition reflects PERSISTED tests (§49) — candidates are
    // only marked duplicate once executed tests exist with that fingerprint.
    const replan = await stack.reasoning.testCandidates(engagement.engagementId);
    const sameFingerprint = replan.items.find((candidate) => candidate.fingerprint === comparison!.fingerprint);
    expect(sameFingerprint).toBeDefined();
    expect(sameFingerprint!.preconditions.duplicate_absent).toBe(true); // no persisted test yet
  });
});

// ---------------------------------------------------------------------------
// §126: identity A/B -> differential analysis (§24-§28)
// ---------------------------------------------------------------------------

describe('differential testing (§24-§28)', () => {
  it('compares the two identities on the note object and records the result', async () => {
    const result = await stack.reasoning.compareDifferential({
      engagementId: engagement.engagementId,
      baselineRequestId: noteRequestA,
      candidateRequestId: noteRequestB,
    });
    expect(result.recordId).toMatch(/^DF[CR]_/);
    // both identities received the same note content (broken endpoint):
    // status unchanged, schema unchanged; only volatile timestamp-ish noise
    expect(result.summary.status_changed).toBe(false);
    expect(result.summary.schema_changed).toBe(false);

    const rows = await stack.repos.differentialResults.listByEngagement(engagement.engagementId, 50);
    expect(rows.some((row) => row.id === result.recordId)).toBe(true);
    // event emitted (audit trail)
    const events = await stack.repos.events.listByEngagement(engagement.engagementId, 300);
    expect(events.some((event) => event.type === 'DIFFERENTIAL_COMPARISON_RECORDED')).toBe(true);
  });

  it('detects schema changes on the dynamic API variant (Fixture C §26-§27)', async () => {
    const plain = await getAs(stack, engagement.engagementId, null, '/api/items/vary?mode=a');
    const debug = await getAs(stack, engagement.engagementId, null, '/api/items/vary?mode=b');
    expect(plain.status).toBe(200);
    expect(debug.status).toBe(200);
    await settle(200);

    const result = await stack.reasoning.compareDifferential({
      engagementId: engagement.engagementId,
      baselineRequestId: plain.requestId,
      candidateRequestId: debug.requestId,
    });
    expect(result.summary.schema_changed).toBe(true);
    expect(result.summary.fields_added).toContain('debug_trace');
    expect(result.summary.fields_added).toContain('stack');
    // generated_at is volatile -> marked, never deleted (§27)
    expect(result.summary.volatile_fields.some((field) => field.includes('generated_at'))).toBe(true);
  });

  it('rejects comparisons across engagements (scope isolation)', async () => {
    await expect(
      stack.reasoning.compareDifferential({
        engagementId: 'ENG_OTHER',
        baselineRequestId: noteRequestA,
        candidateRequestId: noteRequestB,
      }),
    ).rejects.toMatchObject({ code: 'REQUEST_NOT_FOUND' });
  });
});

// ---------------------------------------------------------------------------
// §72-§75: verification — the skeptical engine
// ---------------------------------------------------------------------------

describe('verification engine (§70-§75, §128)', () => {
  it('evaluates the authorization hypothesis skeptically with alternatives', async () => {
    const hypothesis = await stack.repos.hypotheses.create({
      engagementId: engagement.engagementId,
      type: 'AUTHORIZATION',
      statement: 'Endpoint /api/notes/{id} may not enforce object-level ownership',
      status: 'ACTIVE',
      confidence: 0.6,
      priority: 0.8,
      source: 'system',
      parentHypothesisId: null,
    });

    // Record the differential linked to the hypothesis first (§100 baseline).
    await stack.reasoning.compareDifferential({
      engagementId: engagement.engagementId,
      baselineRequestId: noteRequestA,
      candidateRequestId: noteRequestB,
      hypothesisId: hypothesis.id,
    });

    const { verification, outcome } = await stack.reasoning.verify({
      engagementId: engagement.engagementId,
      hypothesisId: hypothesis.id,
    });
    expect(verification.id).toMatch(/^VER_/);
    // The verdict is one of the honest outcomes — never a guess.
    expect(['VERIFIED', 'REFUTED', 'INCONCLUSIVE']).toContain(outcome.status);
    // The checklist runs the §72 alternative explanations
    const checkNames = verification.checklist.map((check) => check.check);
    expect(checkNames).toContain('IS_OBJECT_PUBLIC');
    expect(checkNames).toContain('IS_RESPONSE_CACHED');
    expect(checkNames).toContain('IS_SHARED_ACCESS_LEGITIMATE');
    expect(checkNames).toContain('DOES_BEHAVIOR_REPRODUCE');
    expect(checkNames).toContain('DOES_BASELINE_DIFFER');
    // anonymous access WAS denied (noteRequestAnonymous) -> public alternative refuted
    expect(noteRequestAnonymous).toMatch(/^REQ_/);
    const publicCheck = verification.checklist.find((check) => check.check === 'IS_OBJECT_PUBLIC')!;
    expect(publicCheck.status).toBe('FAIL');
    // alternatives preserved for audit (§74)
    expect(verification.alternatives.length).toBeGreaterThanOrEqual(2);
    // evidence strength classification is explainable (§70)
    expect(String(verification.result['evidence_strength'])).toBeTruthy();

    // verification events emitted
    const events = await stack.repos.events.listByEngagement(engagement.engagementId, 400);
    expect(events.some((event) => event.type === 'VERIFICATION_COMPLETED')).toBe(true);
  });

  it('provides a dead-end payload when the hypothesis is refuted (§75)', async () => {
    const hypothesis = await stack.repos.hypotheses.create({
      engagementId: engagement.engagementId,
      type: 'AUTHORIZATION',
      statement: 'Refuted hypothesis for dead-end recording',
      status: 'DISPROVED',
      confidence: 0.2,
      priority: 0.1,
      source: 'system',
      parentHypothesisId: null,
    });
    const { verification } = await stack.reasoning.verify({
      engagementId: engagement.engagementId,
      hypothesisId: hypothesis.id,
    });
    const payload = stack.reasoning.deadEndFor(verification, {
      id: hypothesis.id,
      statement: hypothesis.statement,
    });
    expect(payload.description).toContain('Refuted hypothesis');
    expect(payload.reason.length).toBeGreaterThan(0);
    expect(Array.isArray(payload.tests)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §111: idempotency + §112: failure isolation
// ---------------------------------------------------------------------------

describe('idempotency and failure isolation (§111-§112)', () => {
  it('re-ingestion produces no duplicate endpoints, parameters or signals', async () => {
    // Absorb requests recorded after the initial ingest (differential tests)
    await stack.reasoning.ingest(engagement.engagementId);
    const before = await stack.reasoning.status(engagement.engagementId);
    await stack.reasoning.ingest(engagement.engagementId);
    await stack.reasoning.ingest(engagement.engagementId);
    const after = await stack.reasoning.status(engagement.engagementId);

    expect(after.counts.endpoints).toBe(before.counts.endpoints);
    // parameters and matrix are upserts: counts stay stable
    expect(after.counts.parameters).toBe(before.counts.parameters);
    expect(after.counts.matrix_entries).toBe(before.counts.matrix_entries);
    // signals are fingerprint-deduped: no explosion
    expect(after.counts.signals).toBe(before.counts.signals);
    // no processor failures were recorded during healthy re-ingestion
    expect(after.counts.processor_failures).toBe(0);
  });

  it('status reports counts and recent failures bounded (§113 API)', async () => {
    const status = await stack.reasoning.status(engagement.engagementId);
    expect(status.counts.endpoints).toBeGreaterThan(4);
    expect(status.counts.signals).toBeGreaterThan(0);
    expect(status.counts.workflows).toBeGreaterThan(0);
    expect(status.counts.differentials).toBeGreaterThan(0);
    expect(status.counts.graph_nodes).toBeGreaterThan(0);
    expect(status.counts.graph_edges).toBeGreaterThan(0);
    expect(Array.isArray(status.recent_failures)).toBe(true);
    expect(status.recent_failures.length).toBeLessThanOrEqual(10);
  });
});

// ---------------------------------------------------------------------------
// §120: leader projection + §80 focused query
// ---------------------------------------------------------------------------

describe('leader projection and focused query (§80, §120)', () => {
  it('builds the compact security projection', async () => {
    const projection = await stack.reasoning.buildSecurityProjection(engagement.engagementId);
    expect(projection.attack_surface.endpoint_count).toBeGreaterThan(4);
    expect(projection.attack_surface.identity_count).toBeGreaterThanOrEqual(2);
    expect(projection.attack_surface.workflow_count).toBeGreaterThanOrEqual(1);
    expect(projection.attack_surface.top_endpoints.length).toBeGreaterThan(0);
    for (const endpoint of projection.attack_surface.top_endpoints) {
      expect(endpoint.method_summary).toMatch(/GET|POST/);
      expect(endpoint.priority).toBeGreaterThanOrEqual(0);
      expect(endpoint.priority).toBeLessThanOrEqual(1);
    }
    expect(projection.active_hypotheses.length).toBeGreaterThan(0);
    expect(projection.recommended_tests.length).toBeGreaterThan(0);
    // interesting items are signals with confidences — never conclusions
    for (const item of projection.interesting) {
      expect(item.confidence).toBeGreaterThanOrEqual(0);
      expect(item.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('answers the focused query bounded (§80)', async () => {
    const endpoints = await stack.repos.endpoints.listByEngagement(engagement.engagementId, { limit: 200 });
    const notes = endpoints.find((endpoint) => endpoint.canonical_path === '/api/notes/{param}')!;
    const focused = await stack.reasoning.query({
      engagementId: engagement.engagementId,
      endpointId: notes.id,
    });
    expect(focused.endpoints).toHaveLength(1);
    expect(focused.endpoints[0]!.id).toBe(notes.id);
    expect(focused.parameters.length).toBeGreaterThan(0);
    expect(focused.matrix.length).toBeGreaterThan(0);
    expect(focused.endpoints.length).toBeLessThanOrEqual(16);
    expect(focused.parameters.length).toBeLessThanOrEqual(64);
  });
});
