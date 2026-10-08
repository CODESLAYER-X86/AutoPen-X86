/**
 * Integration: agent state persistence + crash recovery (spec Part 2
 * §63-§65) and idempotency keys.
 *
 * The agent must be restartable: state lives in the DB, not memory. RUNNING
 * tasks during a crash become RECOVERY_PENDING; recovery finalizes from
 * recorded output when possible, re-queues idempotent work, and refuses to
 * blindly replay possibly state-changing operations.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createAgentTestContext, seedEngagement, type AgentTestContext } from './agent-helpers.js';
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
  ctx.strategicScript.length = 0;
  ctx.tacticalScript.length = 0;
});

describe('crash recovery (spec Part 2 §63-§64)', () => {
  it('finalizes a task from recorded output when the attempt completed before the crash', async () => {
    const { engagement } = await seedEngagement(ctx);
    const hypothesis = await ctx.repos.hypotheses.create({
      engagementId: engagement.id,
      type: 'AUTHORIZATION',
      statement: 'Object endpoint lacks authorization.',
      confidence: 0.7,
      priority: 0.6,
      source: 'leader',
    });

    // Simulate a crash mid-run: task stuck in RUNNING with a COMPLETED
    // attempt whose output was recorded before the process died.
    const task = await ctx.repos.tasks.create({
      engagementId: engagement.id,
      runId: null,
      decisionId: null,
      hypothesisId: hypothesis.id,
      type: 'AUTHORIZATION_ANALYSIS',
      objective: 'Compare responses across identities.',
      workerType: 'HTTP_WORKER',
      priority: 0.8,
      dependsOn: [],
      allowedTools: [],
      constraints: {},
      inputs: {},
      idempotencyKey: 'crash-test-1',
    });
    await ctx.repos.tasks.updateStatus(task.id, 'RUNNING');
    await ctx.repos.tasks.incrementAttempts(task.id);
    const attempt = await ctx.repos.taskAttempts.create({
      taskId: task.id,
      engagementId: engagement.id,
      attempt: 1,
      workerType: 'HTTP_WORKER',
      workerModel: 'mock',
    });
    await ctx.repos.taskAttempts.finish(attempt.id, {
      status: 'COMPLETED',
      output: {
        task_id: task.id,
        attempt_id: attempt.id,
        status: 'COMPLETED',
        observations: [
          { type: 'AUTHORIZATION_BEHAVIOR', description: 'Identity A received Identity B data.', confidence: 0.9 },
        ],
        evidence_ids: [],
        hypothesis_updates: [{ hypothesis_id: hypothesis.id, change: 'INCREASE_CONFIDENCE', confidence: 0.3 }],
        usage: { inputTokens: 100, outputTokens: 50, toolCalls: 0, networkRequests: 0, durationMs: 10 },
      },
      toolCalls: 0,
      inputTokens: 100,
      outputTokens: 50,
      durationMs: 10,
    });

    // Recovery (fresh engine, no memory of the previous process).
    const engine = ctx.newEngine();
    const report = await engine.recoverNow(engagement.id);
    expect(report.recovered).toBe(1);
    expect(report.finalizedFromOutput).toBe(1);

    const recovered = await ctx.repos.tasks.findById(task.id);
    expect(recovered!.status).toBe('COMPLETED');
    // The recorded observation was applied (no duplicate network action).
    const observations = await ctx.repos.observations.listByEngagement(engagement.id, 50);
    expect(observations.some((o) => o.type === 'AUTHORIZATION_BEHAVIOR')).toBe(true);
    // Hypothesis confidence was updated from the recovered output.
    const updated = await ctx.repos.hypotheses.findById(hypothesis.id);
    expect(updated!.confidence).toBeGreaterThan(0.7);
  });

  it('re-queues idempotent task types and refuses to replay state-changing ones (§65)', async () => {
    const { engagement } = await seedEngagement(ctx);

    const idempotent = await ctx.repos.tasks.create({
      engagementId: engagement.id,
      runId: null,
      decisionId: null,
      hypothesisId: null,
      type: 'RECON',
      objective: 'Map the API surface.',
      workerType: 'HTTP_WORKER',
      priority: 0.6,
      dependsOn: [],
      allowedTools: [],
      constraints: {},
      inputs: {},
      idempotencyKey: 'crash-recon',
    });
    const stateChanging = await ctx.repos.tasks.create({
      engagementId: engagement.id,
      runId: null,
      decisionId: null,
      hypothesisId: null,
      type: 'AUTHORIZATION_ANALYSIS',
      objective: 'Mutate object identifiers.',
      workerType: 'HTTP_WORKER',
      priority: 0.6,
      dependsOn: [],
      allowedTools: [],
      constraints: {},
      inputs: {},
      idempotencyKey: 'crash-authz',
    });
    // Both stuck RUNNING with NO recorded attempt output.
    await ctx.repos.tasks.updateStatus(idempotent.id, 'RUNNING');
    await ctx.repos.tasks.updateStatus(stateChanging.id, 'RUNNING');

    const engine = ctx.newEngine();
    const report = await engine.recoverNow(engagement.id);

    expect(report.recovered).toBe(2);
    expect(report.requeued).toBe(1);
    expect(report.failed).toBe(1);
    // Detail actions are auditable.
    expect(report.details.find((d) => d.task_id === idempotent.id)?.action).toBe('REQUEUED');
    expect(report.details.find((d) => d.task_id === stateChanging.id)?.action).toBe('FAILED');

    const afterIdempotent = await ctx.repos.tasks.findById(idempotent.id);
    expect(afterIdempotent!.status).toBe('READY');
    const afterStateChanging = await ctx.repos.tasks.findById(stateChanging.id);
    expect(afterStateChanging!.status).toBe('FAILED');
    expect(afterStateChanging!.failure_code).toBe('RECOVERY_UNCERTAIN');
  });

  it('RECOVERY_PENDING events are emitted for dangling RUNNING tasks (§64)', async () => {
    const { engagement } = await seedEngagement(ctx);
    const task = await ctx.repos.tasks.create({
      engagementId: engagement.id,
      runId: null,
      decisionId: null,
      hypothesisId: null,
      type: 'GENERAL_ANALYSIS',
      objective: 'Analysis that crashed mid-flight.',
      workerType: 'ANALYSIS_WORKER',
      priority: 0.5,
      dependsOn: [],
      allowedTools: [],
      constraints: {},
      inputs: {},
      idempotencyKey: 'crash-events',
    });
    await ctx.repos.tasks.updateStatus(task.id, 'RUNNING');

    const engine = ctx.newEngine();
    await engine.recoverNow(engagement.id);

    const events = await ctx.repos.events.listByEngagement(engagement.id, 100);
    expect(events.some((e) => e.type === 'TASK_RECOVERY_PENDING')).toBe(true);
  });
});

describe('idempotency (spec Part 2 §65)', () => {
  it('task creation is idempotent per (engagement, idempotency_key)', async () => {
    const { engagement } = await seedEngagement(ctx);
    const input = {
      engagementId: engagement.id,
      runId: null,
      decisionId: null,
      hypothesisId: null,
      type: 'RECON' as const,
      objective: 'Map the attack surface once.',
      workerType: 'HTTP_WORKER' as const,
      priority: 0.7,
      dependsOn: [],
      allowedTools: [],
      constraints: {},
      inputs: {},
      idempotencyKey: 'idem-1',
    };
    const first = await ctx.repos.tasks.create(input);
    const second = await ctx.repos.tasks.create(input);
    expect(second.id).toBe(first.id);
    const tasks = await ctx.repos.tasks.listByEngagement(engagement.id, {});
    expect(tasks.length).toBe(1);
  });

  it('event insertion with a dedup_key is replay-safe', async () => {
    const { engagement } = await seedEngagement(ctx);
    const event = {
      type: 'AGENT_RUN_CREATED' as const,
      engagement_id: engagement.id,
      task_id: null,
      trace_id: null,
      actor_id: null,
      payload: { replay: true },
      occurred_at: new Date().toISOString(),
      dedup_key: 'dedup-test-1',
    };
    await ctx.repos.events.insert(event);
    await ctx.repos.events.insert(event); // replay after crash
    const events = await ctx.repos.events.listByEngagement(engagement.id, 100);
    expect(events.filter((e) => e.dedup_key === 'dedup-test-1')).toHaveLength(1);
  });
});
