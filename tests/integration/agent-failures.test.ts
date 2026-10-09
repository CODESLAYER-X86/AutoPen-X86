/**
 * Integration: quota simulation (spec Part 2 §74) and failure simulation
 * (spec Part 2 §75). The system must delay work, reschedule, avoid infinite
 * retries, prioritize important tasks, and fail gracefully.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TimeoutError, QuotaError } from '@aegis/shared';
import { createAgentTestContext, seedEngagement, startRun, type AgentTestContext } from './agent-helpers.js';
import { resetDatabase } from './helpers.js';

let ctx: AgentTestContext;

beforeAll(async () => {
  ctx = await createAgentTestContext({ loop: { maxCycles: 4, maxWaitMs: 30, retryDelayMs: 20 } });
});

afterAll(async () => {
  await ctx.close();
});

beforeEach(async () => {
  await resetDatabase(ctx.pool);
  ctx.strategicScript.length = 0;
  ctx.tacticalScript.length = 0;
  // Quota state is shared across engines in this context: reset it so the
  // quota-pressure tests do not starve the failure-simulation tests.
  ctx.quota.reset();
});

describe('quota simulation (spec Part 2 §74)', () => {
  it('delays work when input TPM is low instead of exceeding quota', async () => {
    ctx.quota.recordUsage(119_995, 0); // near the 120k default input TPM
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'needs a hypothesis',
      change: 'CREATE',
      hypothesis: { type: 'UNKNOWN', statement: 'Something about the target is unexplained.', confidence: 0.4 },
    });

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    // The decision was rejected for quota; the run WAITED (not crashed) and
    // eventually ended on the cycle budget. No task was ever dispatched.
    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    expect(decisions.some((d) => d.rejection_code === 'QUOTA_DELAY_REQUIRED')).toBe(true);
    expect((await ctx.repos.tasks.listByEngagement(engagement.id, {})).length).toBe(0);
    expect(run.status).toBe('COMPLETED');
    const events = await ctx.repos.events.listByEngagement(engagement.id, 300);
    expect(events.some((e) => e.type === 'QUOTA_DELAY')).toBe(true);
  });

  it('blocks dispatch when RPM is exhausted', async () => {
    ctx.quota.recordUsage(0, 0);
    ctx.quota.recordUsage(0, 0);
    ctx.quota.recordUsage(0, 0);
    ctx.quota.recordUsage(0, 0);
    ctx.quota.recordUsage(0, 0);
    ctx.quota.recordUsage(0, 0);
    // Default RPM 60: flood the window via the public API.
    for (let i = 0; i < 59; i += 1) ctx.quota.recordUsage(0, 0);
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push({
      decision: 'UPDATE_HYPOTHESIS',
      reasoning_summary: 'needs a hypothesis',
      change: 'CREATE',
      hypothesis: { type: 'UNKNOWN', statement: 'Something about the target is unexplained.', confidence: 0.4 },
    });

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    expect(decisions.some((d) => d.rejection_code === 'QUOTA_DELAY_REQUIRED')).toBe(true);
    expect((await ctx.repos.tasks.listByEngagement(engagement.id, {})).length).toBe(0);
  });

  it('blocks dispatch when the daily request quota is exhausted', async () => {
    // Isolated context: requestsPerDay 1. The first leader call consumes the
    // daily slot; the second cycle must be refused deterministically.
    const isolated = await createAgentTestContext({ quota: { requestsPerDay: 1 } });
    try {
      await resetDatabase(isolated.pool);
      const { engagement } = await seedEngagement(isolated);
      isolated.strategicScript.push(
        {
          decision: 'UPDATE_HYPOTHESIS',
          reasoning_summary: 'needs a hypothesis',
          change: 'CREATE',
          hypothesis: { type: 'UNKNOWN', statement: 'Something about the target is unexplained.', confidence: 0.4 },
        },
        {
          decision: 'UPDATE_HYPOTHESIS',
          reasoning_summary: 'second decision must be quota-blocked',
          change: 'ACTIVATE',
        },
      );

      const engine = isolated.newEngine();
      await startRun(isolated, engagement, engine);
      await engine.run();

      const run = (await isolated.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
      const decisions = await isolated.repos.agentDecisions.listByRun(run.id, 50);
      expect(decisions.some((d) => d.rejection_code === 'QUOTA_DELAY_REQUIRED')).toBe(true);
      expect(run.status).not.toBe('FAILED');
    } finally {
      await isolated.close();
    }
  });
});

describe('failure simulation (spec Part 2 §75)', () => {
  it('leader invalid JSON is rejected gracefully and fails the run after tolerance', async () => {
    const { engagement } = await seedEngagement(ctx);
    // Keep an actionable hypothesis so the deterministic
    // no-actionable-hypotheses stop does not fire before the tolerance.
    await ctx.repos.hypotheses.create({
      engagementId: engagement.id,
      type: 'UNKNOWN',
      statement: 'The target behavior is not yet understood.',
      confidence: 0.3,
      priority: 0.5,
      source: 'human',
    });
    // Model returns prose instead of JSON.
    ctx.strategicScript.push(
      'I cannot answer in JSON, sorry!',
      'Also not JSON.',
      'Still not JSON.',
      'Not JSON either.',
    );

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const run = (await ctx.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    expect(run.status).toBe('FAILED');
    const decisions = await ctx.repos.agentDecisions.listByRun(run.id, 50);
    expect(decisions.length).toBeGreaterThanOrEqual(2);
    for (const decision of decisions) {
      expect(decision.validation_status).toBe('REJECTED');
      expect(decision.rejection_code).toBe('LEADER_DECISION_NOT_JSON');
    }
    const events = await ctx.repos.events.listByEngagement(engagement.id, 300);
    expect(events.some((e) => e.type === 'LEADER_DECISION_REJECTED')).toBe(true);
    // The engagement survives (worker failure never crashes the engagement).
    const finalEngagement = await ctx.repos.engagements.findById(engagement.id);
    expect(finalEngagement!.status).toBe('RUNNING');
  });

  it('worker invalid JSON fails the task permanently without retries', async () => {
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'needs a hypothesis',
        change: 'CREATE',
        hypothesis: { type: 'UNKNOWN', statement: 'Worker output quality is unknown.', confidence: 0.4 },
      },
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'probe worker output',
        task: { objective: 'Produce an observation from the provided context.', task_type: 'GENERAL_ANALYSIS' },
      },
    );
    // Worker emits garbage repeatedly -> bounded invalid-turn feedback -> FAIL.
    ctx.tacticalScript.push('garbage not json', '{ invalid', '{"type":"NOPE"}');

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    const task = tasks.find((t) => t.type === 'GENERAL_ANALYSIS');
    expect(task).toBeDefined();
    expect(task!.status).toBe('FAILED');
    expect(task!.failure_code).toBe('WORKER_TURN_INVALID');
    // Permanent failure: no retry (§44).
    expect(task!.attempts).toBe(1);
  });

  it('worker timeouts retry with bounded attempts then fail the task', async () => {
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'needs a hypothesis',
        change: 'CREATE',
        hypothesis: { type: 'UNKNOWN', statement: 'The worker will time out.', confidence: 0.4 },
      },
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'trigger worker timeouts',
        task: { objective: 'Exercise the timeout retry path.', task_type: 'GENERAL_ANALYSIS' },
      },
    );
    // Every worker call times out (transient -> retryable, bounded).
    ctx.tacticalScript.push(
      new TimeoutError('worker model timeout'),
      new TimeoutError('worker model timeout'),
      new TimeoutError('worker model timeout'),
      new TimeoutError('worker model timeout'),
      new TimeoutError('worker model timeout'),
      new TimeoutError('worker model timeout'),
    );

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    const task = tasks.find((t) => t.type === 'GENERAL_ANALYSIS');
    expect(task).toBeDefined();
    expect(task!.status).toBe('FAILED');
    // Bounded retries: max_attempts 3, never infinite (§74).
    expect(task!.attempts).toBe(3);
    const events = await ctx.repos.events.listByEngagement(engagement.id, 300);
    expect(events.some((e) => e.type === 'TASK_RETRY')).toBe(true);
    expect(events.some((e) => e.type === 'TASK_FAILED')).toBe(true);
  });

  it('provider 429 (QuotaError) is retried and recorded, never crashes the engagement', async () => {
    // Isolated context: deterministic retry counting, no cross-test state.
    const isolated = await createAgentTestContext();
    try {
      await resetDatabase(isolated.pool);
      const { engagement } = await seedEngagement(isolated);
      await isolated.repos.hypotheses.create({
        engagementId: engagement.id,
        type: 'UNKNOWN',
        statement: 'Provider behavior is being exercised.',
        confidence: 0.3,
        priority: 0.5,
        source: 'human',
      });
      for (let i = 0; i < 6; i += 1) isolated.strategicScript.push(new QuotaError('rate limited'));

      const engine = isolated.newEngine();
      await startRun(isolated, engagement, engine);
      await engine.run();
      await verify429(isolated, engagement);
    } finally {
      await isolated.close();
    }
  });

  async function verify429(
    isolated: AgentTestContext,
    engagement: { id: string },
  ): Promise<void> {
    // Two leader cycles x 3 bounded retries = 6 model calls, then the run
    // fails deterministically (idle tolerance) without further calls.
    expect(isolated.strategicCalls.length).toBe(6);
    const run = (await isolated.repos.agentRuns.listByEngagement(engagement.id, 1))[0]!;
    expect(run.status).toBe('FAILED');
    // Each failed decide cycle records a FAILED model call with its code.
    const calls = await isolated.repos.modelCalls.listByRun(run.id);
    const failed = calls.filter((c) => c.status === 'FAILED');
    expect(failed.length).toBe(2);
    for (const call of failed) expect(call.error_code).toBe('QUOTA_EXCEEDED');
    const finalEngagement = await isolated.repos.engagements.findById(engagement.id);
    expect(finalEngagement!.status).toBe('RUNNING');
  }

  it('unavailable tools produce structured NEEDS_TOOL failures, honestly', async () => {
    const { engagement } = await seedEngagement(ctx);
    ctx.strategicScript.push(
      {
        decision: 'UPDATE_HYPOTHESIS',
        reasoning_summary: 'needs a hypothesis',
        change: 'CREATE',
        hypothesis: { type: 'UNKNOWN', statement: 'Prior CVEs may explain the endpoint behavior.', confidence: 0.4 },
      },
      {
        decision: 'CREATE_TASK',
        reasoning_summary: 'search prior knowledge for the observed pattern',
        // knowledge.search is still a registered-but-unimplemented tool
        // (Part 5) — the honest 501 surface this test exercises.
        task: { objective: 'Search prior knowledge.', task_type: 'KNOWLEDGE_SUMMARY', allowed_tools: ['knowledge.search'] },
      },
    );
    // Worker: request the (honestly unimplemented) tool, observe the
    // structured error, then finalize with NEEDS_TOOL.
    ctx.tacticalScript.push(
      { type: 'TOOL_CALL', tool: 'knowledge.search', input: { query: 'prior cve' } },
      {
        type: 'FINAL',
        result: {
          task_id: 'AUTO',
          status: 'NEEDS_TOOL',
          observations: [],
          evidence_ids: [],
          hypothesis_updates: [],
          needs: { tools: ['knowledge.search'] },
        },
      },
    );

    const engine = ctx.newEngine();
    await startRun(ctx, engagement, engine);
    await engine.run();

    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    const task = tasks.find((t) => t.type === 'KNOWLEDGE_SUMMARY');
    expect(task).toBeDefined();
    expect(task!.status).toBe('FAILED');
    expect(task!.failure_code).toBe('WORKER_NEEDS_TOOL');
    // The structured needs survive into the task result for the leader.
    expect((task!.result as { needs?: { tools?: string[] } })?.needs?.tools).toContain('knowledge.search');
  });
});
