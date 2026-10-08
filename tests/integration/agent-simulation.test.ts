/**
 * Integration: deterministic autonomous simulation (spec Part 2 §73).
 *
 * Scenario (from the spec):
 *   Observation 1: endpoint discovered
 *   Leader: create authentication task
 *   Worker: authentication succeeds
 *   Observation 2: object endpoint discovered
 *   Leader: create authorization test
 *   Worker: unexpected cross-identity response
 *   Leader: create verification task
 *   Worker: reproduces behavior
 *   Leader: promote hypothesis
 *
 * The orchestrator must follow the expected state transitions. No real
 * external target; the worker model is scripted, the pipeline is real.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createAgentTestContext, seedEngagement, startRun, type AgentTestContext } from './agent-helpers.js';
import { resetDatabase } from './helpers.js';

let ctx: AgentTestContext;

beforeAll(async () => {
  ctx = await createAgentTestContext({ loop: { maxCycles: 14 } });
});

afterAll(async () => {
  await ctx.close();
});

beforeEach(async () => {
  await resetDatabase(ctx.pool);
  ctx.strategicScript.length = 0;
  ctx.tacticalScript.length = 0;
});

describe('autonomous simulation (spec Part 2 §73)', () => {
  it('follows the expected state transitions end to end', async () => {
    const { engagement } = await seedEngagement(ctx);

    // Seed "Observation 1: endpoint discovered" as prior system context.
    await ctx.repos.observations.create({
      engagementId: engagement.id,
      taskId: null,
      hypothesisId: null,
      type: 'ENDPOINT_DISCOVERED',
      description: 'GET /api/session (authentication) and POST /api/login discovered.',
      confidence: 0.9,
      metadata: { source: 'human', endpoint: '/api/session' },
    });

    const engine = ctx.newEngine();

    // --- Cycle 1: leader forms a hypothesis about the auth flow. ---
    ctx.strategicScript.push({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'Authentication flow exists; sessions may grant object access.',
      change: 'CREATE',
      hypothesis: {
        type: 'AUTHENTICATION',
        statement: 'The login endpoint issues sessions that grant access to object endpoints.',
        confidence: 0.5,
      },
    });
    await startRun(ctx, engagement, engine);
    await engine.step();
    const authHypothesis = (await ctx.repos.hypotheses.listByEngagement(engagement.id, {}))[0]!;
    expect(authHypothesis).toBeDefined();

    // --- Cycle 2: leader creates the authentication task. ---
    ctx.strategicScript.push({
      decision: 'CREATE_TASK',
      reasoning_summary: 'Authenticate with the provided identity to obtain a session.',
      task: {
        objective: 'Authenticate and record session behavior.',
        task_type: 'AUTHENTICATION_ANALYSIS',
        hypothesis_id: authHypothesis.id,
        expected_information_gain: 0.8,
        inputs: { endpoint: '/api/login' },
      },
    });
    // Worker: authentication succeeds.
    ctx.tacticalScript.push({
      task_id: 'AUTO',
      status: 'COMPLETED',
      observations: [
        { type: 'AUTHENTICATION_RESULT', description: 'Authentication succeeded; session cookie issued.', confidence: 0.95 },
      ],
      evidence_ids: [],
      hypothesis_updates: [{ hypothesis_id: authHypothesis.id, change: 'INCREASE_CONFIDENCE', confidence: 0.4 }],
    });
    await engine.step(); // applies decision
    await engine.step(); // dispatches + executes the task

    const authTask = (await ctx.repos.tasks.listByEngagement(engagement.id, {})).find(
      (t) => t.type === 'AUTHENTICATION_ANALYSIS',
    )!;
    expect(authTask.status).toBe('COMPLETED');
    const authHypothesisAfter = await ctx.repos.hypotheses.findById(authHypothesis.id);
    expect(authHypothesisAfter!.confidence).toBeGreaterThan(0.5);

    // --- Observation 2: object endpoint discovered (worker-side discovery). ---
    // (The auth worker's observation is already recorded; the object
    // endpoint appears as a second observation from the next task.)

    // --- Cycle 3: leader suspects an object authorization flaw. ---
    ctx.strategicScript.push({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'Object identifiers were observed; authorization behavior not yet compared.',
      change: 'CREATE',
      hypothesis: {
        type: 'AUTHORIZATION',
        statement: 'Object endpoint /api/users/{id} returns data for identities other than the caller.',
        confidence: 0.55,
        parent_hypothesis_id: authHypothesis.id,
      },
    });
    await engine.step();
    const objectHypothesis = (await ctx.repos.hypotheses.listByEngagement(engagement.id, {})).find(
      (h) => h.type === 'AUTHORIZATION',
    )!;
    expect(objectHypothesis.parent_hypothesis_id).toBe(authHypothesis.id);

    // --- Cycle 4: leader creates the authorization test. ---
    ctx.strategicScript.push({
      decision: 'CREATE_TASK',
      reasoning_summary: 'Compare object responses across identities.',
      task: {
        objective: 'Request /api/users/{id} as both identities and compare responses.',
        task_type: 'AUTHORIZATION_ANALYSIS',
        hypothesis_id: objectHypothesis.id,
        expected_information_gain: 0.95,
        inputs: { endpoint: '/api/users/{id}', observed_ids: ['381', '382'] },
      },
    });
    // Worker: unexpected cross-identity response.
    ctx.tacticalScript.push({
      task_id: 'AUTO',
      status: 'COMPLETED',
      observations: [
        {
          type: 'AUTHORIZATION_BEHAVIOR',
          description: 'Identity A received object data associated with Identity B.',
          confidence: 0.91,
        },
      ],
      evidence_ids: [],
      hypothesis_updates: [{ hypothesis_id: objectHypothesis.id, change: 'INCREASE_CONFIDENCE', confidence: 0.4 }],
      recommended_next_action: { type: 'VERIFY', reason: 'Repeat with a fresh session.' },
    });
    await engine.step();
    await engine.step();

    const objectTask = (await ctx.repos.tasks.listByEngagement(engagement.id, {})).find(
      (t) => t.type === 'AUTHORIZATION_ANALYSIS',
    )!;
    expect(objectTask.status).toBe('COMPLETED');
    expect(objectTask.hypothesis_id).toBe(objectHypothesis.id);

    const crossObservation = (await ctx.repos.observations.listByEngagement(engagement.id, 50)).find(
      (o) => o.type === 'AUTHORIZATION_BEHAVIOR',
    )!;
    expect(crossObservation).toBeDefined();
    expect(crossObservation.hypothesis_id).toBe(objectHypothesis.id);

    // --- Cycle 5: leader requests verification. ---
    ctx.strategicScript.push({
      decision: 'REQUEST_VERIFICATION',
      reasoning_summary: 'Cross-identity behavior must be reproduced before promotion.',
      hypothesis_id: objectHypothesis.id,
    });
    // Verifier: reproduces the behavior -> CONFIRM.
    ctx.tacticalScript.push({
      task_id: 'AUTO',
      status: 'COMPLETED',
      observations: [
        { type: 'REPRODUCTION', description: 'Cross-identity access reproduced with fresh sessions.', confidence: 0.96 },
      ],
      evidence_ids: [],
      hypothesis_updates: [{ hypothesis_id: objectHypothesis.id, change: 'CONFIRM', confidence: 0.93 }],
    });
    // --- Cycle 6: leader stops with the objective satisfied. ---
    ctx.strategicScript.push({
      decision: 'STOP',
      reasoning_summary: 'Authorization hypothesis confirmed and verified.',
      objective_satisfied: true,
    });

    await engine.run();

    // --- Expected final state (§73: "promote hypothesis"). ---
    const promoted = await ctx.repos.hypotheses.findById(objectHypothesis.id);
    expect(promoted!.status).toBe('CONFIRMED');
    expect(promoted!.confirmed_at).not.toBeNull();

    const findings = await ctx.repos.findings.listByEngagement(engagement.id, {});
    expect(findings.length).toBe(1);
    expect(findings[0]!.status).toBe('CONFIRMED');
    expect(findings[0]!.hypothesis_id).toBe(objectHypothesis.id);

    // Orchestrator state transitions: run COMPLETED, engagement COMPLETED.
    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    expect(run.status).toBe('COMPLETED');
    const finalEngagement = await ctx.repos.engagements.findById(engagement.id);
    expect(finalEngagement!.status).toBe('COMPLETED');

    // Every task terminal and completed.
    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    expect(tasks.length).toBe(3);
    for (const task of tasks) expect(task.status).toBe('COMPLETED');

    // Verification was requested (leader + worker recommendation).
    const events = await ctx.repos.events.listByEngagement(engagement.id, 300);
    expect(events.filter((e) => e.type === 'VERIFICATION_REQUESTED').length).toBeGreaterThanOrEqual(2);
    expect(events.some((e) => e.type === 'HYPOTHESIS_CONFIRMED')).toBe(true);
    expect(events.some((e) => e.type === 'FINDING_CREATED')).toBe(true);
    expect(events.some((e) => e.type === 'AGENT_RUN_COMPLETED')).toBe(true);

    // Decision cycles are reproducible: input state hashes recorded per cycle.
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    expect(decisions.length).toBe(6);
    for (const decision of decisions) {
      expect(decision.validation_status).toBe('VALID');
      expect(decision.input_state_hash).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it('WAIT is a successful decision when evidence is insufficient (§77)', async () => {
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'insufficient evidence to choose a test yet',
        change: 'CREATE',
        hypothesis: { type: 'UNKNOWN', statement: 'The target behavior is not yet understood.', confidence: 0.3 },
      },
      { decision: 'WAIT', reasoning_summary: 'We lack enough evidence to pick a test.' },
      { decision: 'WAIT', reasoning_summary: 'Still waiting.' },
      { decision: 'STOP', reasoning_summary: 'no more useful work', objective_satisfied: true },
    );
    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    const waits = decisions.filter((d) => d.decision_type === 'WAIT');
    expect(waits.length).toBe(2);
    for (const wait of waits) expect(wait.validation_status).toBe('VALID');
    expect(run.status).toBe('COMPLETED');
    // No tasks were created: doing nothing was the right call.
    expect((await ctx.repos.tasks.listByEngagement(engagement.id, {})).length).toBe(0);
  });
});
