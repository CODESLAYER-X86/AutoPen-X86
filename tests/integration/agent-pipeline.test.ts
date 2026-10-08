/**
 * Integration: the full agent pipeline (spec Part 2 §72).
 *
 * leader decision -> task compiler -> scheduler -> mock worker -> result ->
 * observation -> hypothesis update -> leader context.
 * No real external target; tools are the real registry (parser.jwt) with
 * http/browser tools honestly unimplemented.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ContextBuilder } from '@aegis/agent';
import { createAgentTestContext, seedEngagement, startRun, type AgentTestContext } from './agent-helpers.js';
import { resetDatabase } from './helpers.js';

let ctx: AgentTestContext;

beforeAll(async () => {
  ctx = await createAgentTestContext();
});

afterAll(async () => {
  await ctx.close();
});

beforeEach(async () => {
  await resetDatabase(ctx.pool);
  // Scripts are shared arrays: reset them so each test scripts its own run.
  ctx.strategicScript.length = 0;
  ctx.tacticalScript.length = 0;
  ctx.strategicCalls.length = 0;
  ctx.tacticalCalls.length = 0;
});

describe('leader decision -> compiler -> scheduler -> worker -> observation -> hypothesis -> context (§72)', () => {
  it('executes the full deterministic chain against the real database', async () => {
    const { engagement } = await seedEngagement(ctx);

    // Scripted leader: (1) create hypothesis, (2) create a task linked to it,
    // (3) STOP. Cycle 2 needs the real hypothesis id, so cycle 1 runs first.
    ctx.strategicScript.push({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'Two object identifiers were observed; authorization not yet compared.',
      change: 'CREATE',
      hypothesis: {
        type: 'AUTHORIZATION',
        statement: 'Authorization depends only on the object identifier, not the caller.',
        confidence: 0.55,
        priority: 0.8,
      },
    });
    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.step();
    const hypothesis = (await ctx.repos.hypotheses.listByEngagement(engagement.id, {}))[0]!;
    expect(hypothesis).toBeDefined();

    ctx.strategicScript.push(
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'Test object authorization across identities.',
        task: {
          objective: 'Determine whether object authorization is enforced on /api/users/{id}.',
          task_type: 'AUTHORIZATION_ANALYSIS',
          hypothesis_id: hypothesis.id,
          expected_information_gain: 0.9,
          inputs: { endpoint: '/api/users/{id}', observed_ids: ['381', '382'] },
        },
      },
      { decision: 'STOP', reasoning_summary: 'chain demonstrated', objective_satisfied: true },
    );
    // Scripted worker: one structured observation + confidence increase.
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
      hypothesis_updates: [{ change: 'INCREASE_CONFIDENCE', confidence: 0.4 }],
      recommended_next_action: { type: 'VERIFY', reason: 'Repeat with a fresh session.' },
    });

    await engine.run();

    // 1. Hypothesis persisted.
    expect(hypothesis.type).toBe('AUTHORIZATION');
    expect(hypothesis.source).toBe('leader');

    // 2. Task persisted, executed by the mock worker, terminal.
    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    expect(tasks.length).toBe(1);
    const task = tasks[0]!;
    expect(task.status).toBe('COMPLETED');
    expect(task.worker_type).toBe('HTTP_WORKER');
    expect(task.type).toBe('AUTHORIZATION_ANALYSIS');
    expect(task.allowed_tools.length).toBeGreaterThan(0);
    expect(task.attempts).toBe(1);

    // 3. Test registry row created (duplicate prevention).
    const tests = await ctx.repos.tests.listByEngagement(engagement.id, 100);
    expect(tests.length).toBe(1);
    expect(tests[0]!.task_id).toBe(task.id);
    expect(tests[0]!.status).toBe('COMPLETED');

    // 4. Observation persisted with dedup + hypothesis linkage.
    const observations = await ctx.repos.observations.listByEngagement(engagement.id, 50);
    expect(observations.length).toBe(1);
    expect(observations[0]!.type).toBe('AUTHORIZATION_BEHAVIOR');
    expect(observations[0]!.hypothesis_id).toBe(hypothesis.id);

    // 5. Hypothesis confidence increased via the evidence event.
    const updated = await ctx.repos.hypotheses.findById(hypothesis.id);
    expect(updated!.confidence).toBeGreaterThan(0.55);

    // 6. Worker attempt recorded with token usage.
    const attempts = await ctx.repos.taskAttempts.listByTask(task.id);
    expect(attempts.length).toBe(1);
    expect(attempts[0]!.status).toBe('COMPLETED');
    expect(attempts[0]!.input_tokens).toBeGreaterThan(0);

    // 7. Decision records with cycles + outcomes + input state hash.
    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    expect(decisions.length).toBe(3);
    const ordered = [...decisions].sort((a, b) => a.cycle - b.cycle);
    expect(ordered.map((d) => d.decision_type)).toEqual([
      'UPDATE_HYPOTHESIS',
      'CREATE_TASK',
      'STOP',
    ]);
    for (const decision of ordered) {
      expect(decision.validation_status).toBe('VALID');
      expect(decision.input_state_hash).toMatch(/^[a-f0-9]{64}$/);
    }
    expect(ordered[1]!.cycle_outcome).toMatchObject({ tasks_created: 1 });

    // 8. Leader context projection: the next cycle SEES the results.
    const contextBuilder = new ContextBuilder({ repos: ctx.repos, tools: ctx.toolRegistry });
    const context = await contextBuilder.build({
      engagementId: engagement.id,
      maxContextTokens: 24_000,
    });
    expect(context.trusted.hypotheses.some((h) => h.id === hypothesis.id)).toBe(true);
    expect(
      context.untrusted.observation_details.some((o) =>
        (o.description as string).includes('Identity A received'),
      ),
    ).toBe(true);
    expect(context.trusted.recent_tests.length).toBe(1);
    // Untrusted data is labeled separately from trusted context.
    expect((context.trusted.observations[0] as { description?: string }).description).toBeUndefined();

    // 9. Run + engagement completed; VERIFICATION_REQUESTED event emitted.
    expect(run.status).toBe('COMPLETED');
    const finalEngagement = await ctx.repos.engagements.findById(engagement.id);
    expect(finalEngagement!.status).toBe('COMPLETED');
    const events = await ctx.repos.events.listByEngagement(engagement.id, 200);
    expect(events.some((e) => e.type === 'VERIFICATION_REQUESTED')).toBe(true);
    expect(events.some((e) => e.type === 'TASK_CREATED')).toBe(true);
    expect(events.some((e) => e.type === 'TASK_DISPATCHED')).toBe(true);
    expect(events.some((e) => e.type === 'WORKER_COMPLETED')).toBe(true);
    expect(events.some((e) => e.type === 'OBSERVATION_CREATED')).toBe(true);
    expect(events.some((e) => e.type === 'HYPOTHESIS_CREATED')).toBe(true);
    expect(events.some((e) => e.type === 'AGENT_RUN_COMPLETED')).toBe(true);
  });

  it('rejects a duplicate test decision and records the rejection (§10, §28-29)', async () => {
    const { engagement } = await seedEngagement(ctx);
    const sameTask = {
      decision: 'CREATE_TASK' as const,
      reasoning_summary: 'same test again',
      task: {
        objective: 'Determine whether object authorization is enforced on /api/users/{id}.',
        task_type: 'AUTHORIZATION_ANALYSIS' as const,
        inputs: { endpoint: '/api/users/{id}', observed_ids: ['381', '382'] },
      },
    };
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'suspicious object behavior',
        change: 'CREATE',
        hypothesis: { type: 'AUTHORIZATION', statement: 'Object endpoint may lack authorization.', confidence: 0.5 },
      },
      sameTask,
      sameTask,
      { decision: 'STOP', reasoning_summary: 'done', objective_satisfied: true },
    );

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const decisions = await ctx.repos.agentDecisions.listByRun(
      (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!.id,
      50,
    );
    const rejected = decisions.find((d) => d.validation_status === 'REJECTED');
    expect(rejected).toBeDefined();
    expect(rejected!.rejection_code).toBe('TEST_DUPLICATE');

    // Only ONE task was actually created.
    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    expect(tasks.length).toBe(1);
    const events = await ctx.repos.events.listByEngagement(engagement.id, 200);
    expect(events.some((e) => e.type === 'LEADER_DECISION_REJECTED')).toBe(true);
    expect(events.some((e) => e.type === 'TEST_DUPLICATE')).toBe(true);
  });

  it('dependency-aware scheduling: dependents wait then run (§19, §33)', async () => {
    const { engagement } = await seedEngagement(ctx);
    // Leader: a hypothesis, one task, then a second task; then STOP.
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'session handling may be flawed',
        change: 'CREATE',
        hypothesis: { type: 'SESSION', statement: 'Sessions are not invalidated after authentication.', confidence: 0.5 },
      },
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'login first',
        task: { objective: 'Authenticate with the provided identity.', task_type: 'AUTHENTICATION_ANALYSIS' },
      },
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'then replay the endpoint with the session',
        task: {
          objective: 'Replay the authenticated endpoint and compare responses.',
          task_type: 'SESSION_ANALYSIS',
          depends_on: [],
        },
      },
      { decision: 'STOP', reasoning_summary: 'done', objective_satisfied: true },
    );
    ctx.tacticalScript.push(
      { task_id: 'AUTO', status: 'COMPLETED', observations: [], evidence_ids: [], hypothesis_updates: [] },
      { task_id: 'AUTO', status: 'COMPLETED', observations: [], evidence_ids: [], hypothesis_updates: [] },
    );

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    expect(tasks.length).toBe(2);
    for (const task of tasks) expect(task.status).toBe('COMPLETED');
  });

  it('verification is separately schedulable and CONFIRM promotes a finding (§55-§56)', async () => {
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'cross-identity access suspected',
        change: 'CREATE',
        hypothesis: {
          type: 'AUTHORIZATION',
          statement: 'Object endpoint returns other users data without authorization.',
          confidence: 0.7,
        },
      },
    );

    // The verification decision needs the real hypothesis id: run the first
    // cycle step-by-step, then script the rest with the real id.
    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    // Cycle 1: create hypothesis.
    await engine.step();
    const hypothesis = (await ctx.repos.hypotheses.listByEngagement(engagement.id, {}))[0]!;
    expect(hypothesis).toBeDefined();

    // Cycle 2: request verification of the real hypothesis.
    ctx.strategicScript.push({
      decision: 'REQUEST_VERIFICATION',
      reasoning_summary: 'needs reproduction before promotion',
      hypothesis_id: hypothesis.id,
    });
    // Verification worker: skeptical reproduction confirms.
    ctx.tacticalScript.push({
      task_id: 'AUTO',
      status: 'COMPLETED',
      observations: [
        { type: 'REPRODUCTION', description: 'Behavior reproduced with a fresh session.', confidence: 0.95 },
      ],
      evidence_ids: [],
      hypothesis_updates: [{ hypothesis_id: hypothesis.id, change: 'CONFIRM', confidence: 0.95 }],
    });
    // Final leader decision.
    ctx.strategicScript.push({
      decision: 'STOP',
      reasoning_summary: 'objective satisfied',
      objective_satisfied: true,
    });

    await engine.run();

    const verified = await ctx.repos.hypotheses.findById(hypothesis.id);
    expect(verified!.status).toBe('CONFIRMED');
    expect(verified!.confirmed_at).not.toBeNull();

    const findings = await ctx.repos.findings.listByEngagement(engagement.id, {});
    expect(findings.length).toBe(1);
    expect(findings[0]!.hypothesis_id).toBe(hypothesis.id);
    expect(findings[0]!.status).toBe('CONFIRMED');

    const events = await ctx.repos.events.listByEngagement(engagement.id, 300);
    expect(events.some((e) => e.type === 'FINDING_CREATED')).toBe(true);
    expect(events.some((e) => e.type === 'VERIFICATION_REQUESTED')).toBe(true);
    expect(events.some((e) => e.type === 'HYPOTHESIS_CONFIRMED')).toBe(true);
  });
});
