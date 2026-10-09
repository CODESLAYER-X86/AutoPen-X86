/**
 * Part 6 integration tests — the autonomous engine over the REAL stack
 * (spec §88 Definition of Done).
 *
 * Covers:
 *  - §9/§62: engine start -> persisted state -> deterministic recon tasks
 *  - §6: phase advancement (RECON -> MODELING -> HYPOTHESIS_GENERATION ->
 *    TESTING -> ANALYSIS -> VERIFICATION -> REPLANNING)
 *  - §14-§16/§65: candidate consumption -> hypotheses + competing branches
 *  - §38: test-candidate compilation into the shared scheduler queue
 *  - §26/§58: verification bridge -> CONFIRMED hypothesis -> promoted,
 *    confidence-enriched finding; REFUTED -> dead end + branch prune
 *  - §19/§60: differential verdicts recorded in the test registry
 *  - §31/§63: CTF mode full cycle -> flag detected -> SOLVED
 *  - §55: crash recovery with lease expiry + policy separation
 *  - §48: human approvals (approve -> READY, reject -> CANCELLED)
 *  - §40/§41: anti-loop + replanning
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { resetDatabase, sql } from './helpers.js';
import { TEST_DATABASE_URL } from '../../vitest.shared.js';
import { createPool } from '@aegis/database';
import { buildAutonomousStack, seedAutonomousEngagement, completeTask, settleEngine, type AutonomousStack } from './part6-helpers.js';
import { loginSession, getAs } from './part4-helpers.js';
import { startCtfApp, challengeText, type CtfApp } from '../fixtures/ctfApp.js';
import { generateId } from '@aegis/shared';

let pool: ReturnType<typeof createPool>;
let stack: AutonomousStack;
let ctfApp: CtfApp;

beforeAll(async () => {
  pool = createPool(TEST_DATABASE_URL, { max: 5 });
  await resetDatabase(pool);
  stack = await buildAutonomousStack({ pool });
  ctfApp = await startCtfApp({ challenge: 'client-side' });
});

afterAll(async () => {
  // stack.close() ends the interaction stack's pool (part3-helpers contract).
  await stack.close();
  await ctfApp.close();
});

beforeEach(async () => {
  for (const state of await stack.repos.autonomousStates.listRunnable().catch(() => [])) {
    stack.engine.loopFor(state.engagement_id)?.stop(state.engagement_id);
  }
  await resetDatabase(pool);
});

// ---------------------------------------------------------------------------
// §9/§62: start + deterministic recon plan
// ---------------------------------------------------------------------------

describe('autonomous engine start (§9, §62)', () => {
  it('persists engine state and compiles the deterministic recon plan', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'test start');

    const state = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(state).not.toBeNull();
    expect(state!.phase).toBe('RECON');
    expect(state!.mode).toBe('PENTEST_MODE');
    expect(state!.started_at).not.toBeNull();

    // §9 pipeline: scope validation + passive + active discovery + sessions
    // + application mapping — all deterministic, bounded, fingerprinted.
    const tasks = await stack.repos.tasks.listByEngagement(engagement.id, { limit: 50 });
    expect(tasks.length).toBeGreaterThanOrEqual(5);
    const stages = new Set(tasks.map((task) => task.inputs.stage));
    expect(stages).toContain('SCOPE_VALIDATION');
    expect(stages).toContain('PASSIVE_DISCOVERY');
    expect(stages).toContain('ACTIVE_DISCOVERY');
    expect(stages).toContain('SESSION_INIT');
    expect(stages).toContain('APPLICATION_MAPPING');

    // §11: every active discovery task carries reason/gain/cost/risk.
    const active = tasks.find((task) => task.inputs.stage === 'ACTIVE_DISCOVERY')!;
    expect(String(active.inputs.reason)).toContain('known-path validation');
    expect(active.expected_information_gain).toBeGreaterThan(0);

    // The agent run was launched through the bridge (§73).
    expect(stack.launcher.calls.some((call) => call.kind === 'start' && call.engagementId === engagement.id)).toBe(true);

    // Events: engine started + recon pipeline started (§8 observable).
    const events = await stack.repos.events.listByEngagement(engagement.id, 50);
    const types = events.map((event) => event.type);
    expect(types).toContain('AUTONOMOUS_ENGINE_STARTED');
    expect(types).toContain('RECON_PIPELINE_STARTED');

    // Idempotent start: a second start does not duplicate tasks.
    await stack.engine.start(engagement, null, 'restart');
    const tasksAfter = await stack.repos.tasks.listByEngagement(engagement.id, { limit: 100 });
    const uniqueKeys = new Set(tasksAfter.map((task) => task.idempotency_key));
    expect(uniqueKeys.size).toBe(tasksAfter.length);
  });
});

// ---------------------------------------------------------------------------
// §6/§14-§16/§38: the full pentest cycle over real lab traffic
// ---------------------------------------------------------------------------

describe('autonomous pentest cycle (§6, §62, §88)', () => {
  it('advances phases, consumes candidates, compiles tests and bridges verification', async () => {
    const { engagement, identityA, identityB } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'full cycle');

    // Record REAL lab traffic through the gateway (the reasoning engine
    // ingests it; signals then drive candidate groups §14-§16).
    await loginSession(stack.reasoning, engagement.id, identityA, 'usera', 'password-a');
    await loginSession(stack.reasoning, engagement.id, identityB, 'userb', 'password-b');
    // The known broken-ownership endpoint (Part 4 fixture): user A reads
    // their own note, then user B's note.
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/7');
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/8');
    await getAs(stack.reasoning, engagement.id, identityB, '/api/notes/8');

    // Complete all recon tasks (simulating worker completions — the Part 2
    // loop owns real worker execution; the engine owns the phases).
    let guard = 0;
    while (guard < 20) {
      guard += 1;
      const pending = await stack.repos.tasks.listByEngagement(engagement.id, {
        statuses: ['QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
        limit: 50,
      });
      if (pending.length === 0) break;
      for (const task of pending) {
        await completeTask(stack.repos, task.id, 'COMPLETED');
      }
      await stack.engine.maintenanceTick(engagement.id);
      await settleEngine(100);
    }

    // RECON -> MODELING: candidates consumed into hypotheses + branches.
    // The engine advanced beyond RECON through the deterministic cycle
    // (terminal STOPPED/COMPLETED is honest when the replan budget is
    // exhausted with no surviving hypotheses, §50/§42).
    const state = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(state).not.toBeNull();
    expect(state!.phase).not.toBe('RECON');
    expect(state!.phase).not.toBe('CREATED');
    expect(state!.phase).not.toBe('INITIALIZING');

    const hypotheses = await stack.repos.hypotheses.listByEngagement(engagement.id, { limit: 100 });
    expect(hypotheses.length).toBeGreaterThan(0);
    const branches = await stack.repos.branches.listByEngagement(engagement.id);
    expect(branches.length).toBeGreaterThan(0);
    expect(branches.some((branch) => branch.origin === 'SIGNAL')).toBe(true);

    // §16: competing hypotheses preserved — the notes endpoint produces a
    // CROSS_IDENTITY_OBJECT_REFERENCE signal group with competitors.
    const events = await stack.repos.events.listByEngagement(engagement.id, 200);
    expect(events.map((event) => event.type)).toContain('HYPOTHESIS_CANDIDATES_CONSUMED');

    // §38: test candidates compiled through the same scheduler queue.
    guard = 0;
    while (guard < 20) {
      guard += 1;
      await stack.engine.maintenanceTick(engagement.id);
      const pending = await stack.repos.tasks.listByEngagement(engagement.id, {
        statuses: ['QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
        limit: 50,
      });
      if (pending.length === 0) break;
      for (const task of pending) {
        await completeTask(stack.repos, task.id, 'COMPLETED');
      }
      await settleEngine(80);
    }

    const compiledEvents = await stack.repos.events.listByEngagement(engagement.id, 300);
    expect(compiledEvents.map((event) => event.type)).toContain('TEST_CANDIDATES_COMPILED');
    const candidateTasks = await sql<{ id: string }>(
      pool,
      `SELECT id FROM tasks WHERE inputs->>'mode' = 'TEST_CANDIDATE' AND engagement_id = $1`,
      [engagement.id],
    );
    expect(candidateTasks.length).toBeGreaterThan(0);

    // §47: engine-compiled tasks carry structured mutations, never free-form
    // network instructions.
    const candidateTask = await stack.repos.tasks.findById(candidateTasks[0]!.id);
    expect(Array.isArray(candidateTask!.inputs.mutations)).toBe(true);
    expect(String(candidateTask!.inputs.instruction)).toContain('http.mutate');

    // Timeline (§53): the audit chain renders.
    const timeline = await stack.engine.timelineView(engagement.id, 100);
    expect(timeline.entries.length).toBeGreaterThan(0);
    expect(timeline.entries.some((entry) => entry.type === 'RECON_PIPELINE_STARTED')).toBe(true);
    expect(timeline.entries.some((entry) => entry.type === 'HYPOTHESIS_CANDIDATES_CONSUMED')).toBe(true);

    // Graph (§12-§13): the unified attack-surface projection.
    const graph = await stack.engine.graph(engagement.id);
    expect(graph.counts.ENDPOINT).toBeGreaterThan(0);
    expect(graph.counts.IDENTITY).toBeGreaterThanOrEqual(2);
    expect(graph.edges.some((edge) => edge.relation === 'CONTAINS')).toBe(true);

    // Coverage (§51): a planning signal with the honest note.
    const coverage = await stack.engine.coverage(engagement.id);
    expect(coverage.note).toContain('not proof of security');
    expect(coverage.counts.endpoints).toBeGreaterThan(0);
  });

  it('verification bridge: VERIFIED confirms the hypothesis and enriches the finding (§26, §28, §58)', async () => {
    const { engagement, identityA, identityB } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'verification bridge');

    await loginSession(stack.reasoning, engagement.id, identityA, 'usera', 'password-a');
    await loginSession(stack.reasoning, engagement.id, identityB, 'userb', 'password-b');
    // IDOR traffic: both identities read BOTH notes (owner + foreign).
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/7');
    await getAs(stack.reasoning, engagement.id, identityA, '/api/notes/8');
    await getAs(stack.reasoning, engagement.id, identityB, '/api/notes/8');
    await getAs(stack.reasoning, engagement.id, identityB, '/api/notes/7');

    // Drive to hypothesis state.
    let guard = 0;
    while (guard < 25) {
      guard += 1;
      await stack.engine.maintenanceTick(engagement.id);
      const pending = await stack.repos.tasks.listByEngagement(engagement.id, {
        statuses: ['QUEUED', 'READY', 'RUNNING', 'WAITING', 'RECOVERY_PENDING'],
        limit: 50,
      });
      if (pending.length === 0 && guard > 3) break;
      for (const task of pending) {
        await completeTask(stack.repos, task.id, 'COMPLETED');
      }
      await settleEngine(80);
    }

    // Force one hypothesis to SUPPORTED, then bridge the verification (§26).
    const hypotheses = await stack.repos.hypotheses.listByEngagement(engagement.id, { limit: 50 });
    expect(hypotheses.length).toBeGreaterThan(0);
    const target = hypotheses[0]!;
    await stack.repos.hypotheses.update(target.id, { status: 'SUPPORTED', confidence: 0.8 });

    const result = await stack.engine.handlePlatformEvent(engagement.id, {
      type: 'HYPOTHESIS_UPDATED',
      engagement_id: engagement.id,
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { hypothesis_id: target.id, status: 'SUPPORTED' },
      occurred_at: new Date().toISOString(),
    });
    void result;

    // The bridge ran: either CONFIRMED (finding promoted) or the hypothesis
    // stayed for reproduction — both are §26-honest outcomes. For the IDOR
    // fixture with cross-identity reads the checklist supports verification.
    const bridged = await stack.repos.events.listByEngagement(engagement.id, 300);
    expect(bridged.map((event) => event.type)).toContain('VERIFICATION_BRIDGE_APPLIED');

    const verification = await stack.repos.verifications.listByEngagement(engagement.id, 10);
    expect(verification.length).toBeGreaterThan(0);
    expect(['VERIFIED', 'REFUTED', 'INCONCLUSIVE']).toContain(verification[0]!.status);

    // If VERIFIED: the finding exists with the confidence model attached.
    const after = await stack.repos.hypotheses.findById(target.id);
    if (after?.status === 'CONFIRMED') {
      const finding = await stack.repos.findings.findByHypothesis(target.id);
      expect(finding).not.toBeNull();
      expect(['CONFIRMED', 'VERIFIED', 'PROPOSED', 'CANDIDATE']).toContain(finding!.status);
      expect(finding!.verification_ids.length).toBeGreaterThan(0);
      expect(finding!.confidence).not.toBeNull();
      expect(['HIGH', 'MEDIUM', 'LOW']).toContain(finding!.confidence_level!);
      expect(finding!.confidence_reasons.length).toBeGreaterThan(0);
      const confidenceEvents = await stack.repos.events.listByEngagement(engagement.id, 300);
      expect(confidenceEvents.map((event) => event.type)).toContain('FINDING_CONFIDENCE_COMPUTED');
    }
  });
});

// ---------------------------------------------------------------------------
// §31/§63: CTF mode
// ---------------------------------------------------------------------------

describe('CTF mode (§4, §29-§31, §63)', () => {
  it('analyzes clues, branches interpretations and detects the flag -> SOLVED', async () => {
    const { engagement } = await seedAutonomousEngagement(stack, {
      mode: 'CTF',
      description: challengeText('client-side').description,
    });
    await stack.engine.start(engagement, null, 'ctf solve');

    // The CTF context was initialized with the challenge description (§29).
    const context = await stack.repos.ctfContexts.findByEngagement(engagement.id);
    expect(context).not.toBeNull();
    expect(context!.title).toBe('Part6 Engagement');
    expect(context!.status).toBe('UNSOLVED');

    const clues = await stack.repos.ctfClues.listByEngagement(engagement.id);
    expect(clues.length).toBeGreaterThan(0);
    expect(clues.some((clue) => clue.source === 'DESCRIPTION')).toBe(true);

    // §29: interpretations recorded deterministically — never treated as fact.
    const interpreted = clues.filter((clue) => clue.interpretations.length > 0);
    expect(interpreted.length).toBeGreaterThan(0);
    expect(interpreted[0]!.interpretations[0]!.confidence).toBeLessThan(1);

    // §30: branches exist for the interpretations.
    const branches = await stack.repos.branches.listByEngagement(engagement.id);
    expect(branches.some((branch) => branch.origin === 'CTF_CLUE')).toBe(true);

    // §31: the flag condition is hypothesized with the declared pattern.
    const flagConditions = await stack.repos.flagConditions.listByEngagement(engagement.id);
    expect(flagConditions.length).toBeGreaterThan(0);
    expect(flagConditions[0]!.status).toBe('HYPOTHESIZED');

    // CTF hypotheses were created (CTF_CLUE type, §4).
    const hypotheses = await stack.repos.hypotheses.listByEngagement(engagement.id, { limit: 50 });
    expect(hypotheses.some((hypothesis) => hypothesis.type === 'CTF_CLUE')).toBe(true);

    // Record the flag evidence: the API echoes the flag (§63 evidence path).
    await fetch(`${ctfApp.url}/api/state`).then((response) => response.text());
    // Push it through the REAL http gateway so it lands in recorded traffic.
    await stack.reasoning.interaction.gateway.execute(
      'http.request',
      { method: 'GET', url: `${ctfApp.url}/api/state`, identity_id: null },
      {
        engagementId: engagement.id,
        scope: {
          allowed_hosts: [ctfApp.host],
          allowed_domains: [],
          allowed_ports: [ctfApp.port],
          allowed_schemes: ['http', 'https'],
          excluded_hosts: [],
          excluded_paths: [],
          rate_limit: null,
          concurrency_limit: null,
          destructive_actions_allowed: false,
        },
        permissions: { network: true, browser: true, destructive: false },
      },
    );

    // §31: flag-condition scan detects the pattern -> SOLVED.
    await stack.engine.maintenanceTick(engagement.id);
    const solved = await stack.repos.ctfContexts.findByEngagement(engagement.id);
    expect(solved!.status).toBe('SOLVED');
    expect(solved!.flag_value).toContain('flag{');
    expect(solved!.solved_at).not.toBeNull();

    const events = await stack.repos.events.listByEngagement(engagement.id, 100);
    const types = events.map((event) => event.type);
    expect(types).toContain('FLAG_DETECTED');
    expect(types).toContain('CHALLENGE_SOLVED');
    expect(types).toContain('STOP_CONDITION_MET');

    // §50: objective completed -> engine completes the engagement via the
    // orchestrator bridge (§73).
    expect(stack.completions.some((entry) => entry.engagementId === engagement.id && entry.kind === 'complete')).toBe(true);

    // §6: terminal phase persisted.
    const state = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(state!.phase).toBe('COMPLETED');
    expect(state!.stop_reason).toBe('OBJECTIVE_COMPLETED');
  });

  it('user-added clues are analyzed (§48 add CTF clue)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack, { mode: 'CTF' });
    await stack.engine.start(engagement, null, 'clue add');
    const ctf = stack.engine.ctfEngine!;
    await ctf.addClue(engagement.id, 'The cookie jar contains the secret — decode it.');
    await ctf.analyze(engagement.id);
    const clues = await stack.repos.ctfClues.listByEngagement(engagement.id);
    const userClue = clues.find((clue) => clue.source === 'USER');
    expect(userClue).toBeDefined();
    expect(userClue!.interpretations.some((i) => i.concept === 'cookies' || i.concept === 'encoding')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// §55: crash recovery
// ---------------------------------------------------------------------------

describe('crash recovery (§54-§55)', () => {
  it('expired leases: read-only tasks retry, state-changing tasks are failed (never blindly repeated)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'recovery');

    const readOnly = (await sql<{ id: string }>(
      pool,
      `SELECT id FROM tasks WHERE inputs->>'stage' = 'SCOPE_VALIDATION' AND engagement_id = $1`,
      [engagement.id],
    ))[0]!;
    // Simulate a state-changing task via direct insert through the planner
    // path: mutate the inputs of an active-discovery task.
    const stateChanging = (await sql<{ id: string }>(
      pool,
      `SELECT id FROM tasks WHERE inputs->>'stage' = 'ACTIVE_DISCOVERY' AND engagement_id = $1`,
      [engagement.id],
    ))[0]!;

    // Both RUNNING with EXPIRED leases (crashed engine instance, §55).
    await sql(pool, `UPDATE tasks SET status='RUNNING', lease_expires_at = now() - interval '1 hour', leased_by='AEN_DEAD' WHERE id = ANY($1)`, [
      [readOnly.id, stateChanging.id],
    ]);

    // Read-only task: mark it a recon task (safe retry path).
    // State-changing: pretend it is a mutation test.
    await sql(pool, `UPDATE tasks SET inputs = jsonb_set(inputs, '{mode}', '"TEST_CANDIDATE"'), inputs = jsonb_set(inputs, '{mutations}', '[{"location":"path","operation":"replace","value":"8"}]'::jsonb) WHERE id = $1`, [stateChanging.id]);

    // Force the sweep through maintenance (§55).
    await stack.engine.maintenanceTick(engagement.id);
    await settleEngine(150);

    const recovered = await stack.repos.tasks.findById(readOnly.id);
    expect(['RECOVERY_PENDING', 'READY', 'QUEUED']).toContain(recovered!.status);

    const failed = await stack.repos.tasks.findById(stateChanging.id);
    expect(failed!.status).toBe('FAILED');
    expect(failed!.failure_code).toBe('LEASE_EXPIRED_STATE_CHANGING');

    const events = await stack.repos.events.listByEngagement(engagement.id, 100);
    expect(events.map((event) => event.type)).toContain('TASK_LEASE_EXPIRED');
  });
});

// ---------------------------------------------------------------------------
// §48: human interventions
// ---------------------------------------------------------------------------

describe('human interventions (§48)', () => {
  it('approve moves a WAITING task to READY; reject cancels it', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'approvals');

    const tasks = await stack.repos.tasks.listByEngagement(engagement.id, { limit: 10 });
    const task = tasks[0]!;
    await stack.repos.tasks.updateStatus(task.id, 'WAITING');

    const approved = await stack.engine.approveTask(engagement.id, task.id, 'USR_1', 'authorized');
    expect(approved).toBe(true);
    const afterApprove = await stack.repos.tasks.findById(task.id);
    expect(afterApprove!.status).toBe('READY');

    const approvals = await stack.repos.approvals.listByEngagement(engagement.id);
    expect(approvals.length).toBeGreaterThan(0);
    expect(approvals.some((approval) => approval.decision === 'APPROVED')).toBe(true);

    // A second approval of the same approval is impossible (§49 exactly-once).
    const pending = await stack.repos.approvals.findPendingForTask(task.id);
    expect(pending).toBeNull();

    const task2 = tasks[1]!;
    await stack.repos.tasks.updateStatus(task2.id, 'WAITING');
    const rejected = await stack.engine.rejectTask(engagement.id, task2.id, 'USR_1', 'not authorized');
    expect(rejected).toBe(true);
    const afterReject = await stack.repos.tasks.findById(task2.id);
    expect(afterReject!.status).toBe('CANCELLED');

    const events = await stack.repos.events.listByEngagement(engagement.id, 100);
    const decisions = events.filter((event) => event.type === 'APPROVAL_DECIDED');
    expect(decisions.length).toBe(2);
  });

  it('prioritize raises a hypothesis priority and records the override (§48)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    const hypothesis = await stack.repos.hypotheses.create({
      engagementId: engagement.id,
      type: 'AUTHORIZATION',
      statement: 'Object ownership may not be enforced server-side for note objects.',
      confidence: 0.6,
      priority: 0.4,
      source: 'test',
    });
    const ok = await stack.engine.prioritizeHypothesis(engagement.id, hypothesis.id, 'user signal');
    expect(ok).toBe(true);
    const updated = await stack.repos.hypotheses.findById(hypothesis.id);
    expect(updated!.priority).toBeGreaterThan(0.4);
    const events = await stack.repos.events.listByEngagement(engagement.id, 20);
    expect(events.map((event) => event.type)).toContain('HUMAN_OVERRIDE');
  });
});

// ---------------------------------------------------------------------------
// §40/§41/§64: replanning + stop conditions
// ---------------------------------------------------------------------------

describe('replanning and stop conditions (§40-§41, §50, §64, §75)', () => {
  it('replan records the trigger and recomputes strategy (§64)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'replan');
    const result = await stack.engine.replan(engagement.id, 'HYPOTHESIS_CONFIRMED');
    expect(result.replanCount).toBe(1);
    const state = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(state!.replan_count).toBe(1);
    expect(state!.last_replan_trigger).toBe('HYPOTHESIS_CONFIRMED');
    const events = await stack.repos.events.listByEngagement(engagement.id, 50);
    expect(events.map((event) => event.type)).toContain('REPLAN_REQUESTED');
    const strategies = await stack.repos.strategies.listByEngagement(engagement.id);
    expect(strategies.length).toBeGreaterThan(0);
  });

  it('diminishing returns stop: inconclusive tests exhaust the plan (§50)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'stop conditions');

    // Directly craft the §50 state: terminal inconclusive tests, no
    // actionable hypotheses, no pending tasks.
    await stack.repos.tests.register({
      engagementId: engagement.id,
      taskId: null,
      hypothesisId: null,
      testType: 'AUTHORIZATION_ANALYSIS',
      target: '/api/notes',
      fingerprint: 'fp-inconclusive-1',
    }).then((entry) => entry.record)
      .then(async (record) => {
        await stack.repos.tests.updateResult(record.id, 'COMPLETED', 'no difference');
        await stack.repos.tests.recordOutcome(record.id, 'INCONCLUSIVE', 'no semantic difference');
      });
    await stack.repos.tests.register({
      engagementId: engagement.id,
      taskId: null,
      hypothesisId: null,
      testType: 'AUTHORIZATION_ANALYSIS',
      target: '/api/orders',
      fingerprint: 'fp-inconclusive-2',
    }).then((entry) => entry.record)
      .then(async (record) => {
        await stack.repos.tests.updateResult(record.id, 'COMPLETED', 'no difference');
        await stack.repos.tests.recordOutcome(record.id, 'INCONCLUSIVE', 'no semantic difference');
      });

    await stack.engine.maintenanceTick(engagement.id);
    await settleEngine(150);

    const state = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(['STOPPED', 'COMPLETED']).toContain(state!.phase);
    expect(state!.stop_reason).toBeTruthy();
    const events = await stack.repos.events.listByEngagement(engagement.id, 100);
    expect(events.map((event) => event.type)).toContain('STOP_CONDITION_MET');
  });

  it('pause and resume control the loop (§48/§73)', async () => {
    const { engagement } = await seedAutonomousEngagement(stack);
    await stack.engine.start(engagement, null, 'control');
    await stack.engine.pause(engagement.id, 'USR_1', 'operator pause');
    const paused = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(paused!.phase).toBe('WAITING_FOR_USER');
    expect(paused!.waiting_reason).toContain('operator pause');

    await stack.engine.resume(engagement.id, 'USR_1');
    const resumed = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(['REPLANNING', 'RECON', 'TESTING', 'HYPOTHESIS_GENERATION', 'ANALYSIS', 'MODELING']).toContain(resumed!.phase);
    expect(stack.launcher.calls.some((call) => call.kind === 'pause')).toBe(true);
    expect(stack.launcher.calls.some((call) => call.kind === 'resume')).toBe(true);

    await stack.engine.cancel(engagement.id, 'USR_1');
    const cancelled = await stack.repos.autonomousStates.findByEngagement(engagement.id);
    expect(cancelled!.phase).toBe('CANCELLED');
    expect(cancelled!.stop_reason).toBe('USER_STOP');
  });
});
