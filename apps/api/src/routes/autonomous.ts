/**
 * Autonomous engine API routes (spec Part 6 §48, §52, §72).
 *
 * Engine control + observability:
 *  - POST /engagements/:id/autonomous/start|pause|resume|cancel|replan
 *  - GET  /engagements/:id/autonomous/status|graph|timeline|coverage|tests
 *  - GET  /engagements/:id/branches|approvals|ctf|verification-queue
 *  - POST /engagements/:id/prioritize|approve|reject
 *  - POST /engagements/:id/ctf/context|clues
 *  - GET  /benchmarks + /benchmarks/:name/runs
 *
 * All routes are ownership-guarded; 501 when the engine is disabled by
 * configuration (honest degradation).
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { NotImplementedError, ValidationError } from '@aegis/shared';
import {
  AddCtfClueRequestSchema,
  ApproveRequestSchema,
  PrioritizeRequestSchema,
  RejectRequestSchema,
  ReplanRequestSchema,
  StartAutonomousRequestSchema,
  UpsertCtfContextRequestSchema,
} from '@aegis/contracts';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

export async function autonomousRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  const engine = () => {
    const c = ctx();
    if (!c.autonomous) {
      throw new NotImplementedError(
        'The autonomous engine (Part 6) is disabled in this deployment; set FEATURE_AUTONOMOUS_ENGINE=true to enable it',
        'AUTONOMOUS_ENGINE_DISABLED',
      );
    }
    return c.autonomous;
  };

  // ------------------------------------------------------------- control (§72)

  app.post('/api/engagements/:id/autonomous/start', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(StartAutonomousRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    if (engagement.status !== 'RUNNING') {
      throw new ValidationError(
        'Engagement must be RUNNING before the autonomous engine starts; start the engagement first',
        'ENGAGEMENT_NOT_RUNNING',
      );
    }
    const result = await engine().start(engagement, request.user.id, body.reason);
    await c.audit({
      actorUserId: request.user.id,
      action: 'AUTONOMOUS_ENGINE_STARTED',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { state_id: result.stateId },
    });
    return reply.code(202).send({ started: true, state_id: result.stateId });
  });

  app.post('/api/engagements/:id/autonomous/pause', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await engine().pause(engagement.id, request.user.id);
    return reply.send({ paused: true });
  });

  app.post('/api/engagements/:id/autonomous/resume', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await engine().resume(engagement.id, request.user.id);
    return reply.send({ resumed: true });
  });

  app.post('/api/engagements/:id/autonomous/cancel', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    await engine().cancel(engagement.id, request.user.id);
    return reply.send({ cancelled: true });
  });

  app.post('/api/engagements/:id/autonomous/replan', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(ReplanRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const result = await engine().replan(engagement.id, body.trigger ?? 'MANUAL');
    return reply.send({
      replanned: true,
      replan_count: result.replanCount,
      phase: (await engine().engineState(engagement.id))?.phase ?? 'REPLANNING',
    });
  });

  // ------------------------------------------------------------- status (§52)

  app.get('/api/engagements/:id/autonomous/status', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const e = engine();
    const state = await e.engineState(engagement.id);
    if (!state) {
      throw new NotImplementedError(
        'No autonomous engine state for this engagement; start the engine first',
        'AUTONOMOUS_ENGINE_NOT_STARTED',
      );
    }
    const [tasks, hypotheses, findings, verifications, budget, run, ctfContext, clues, flagConditions] =
      await Promise.all([
        c.repos.tasks.listByEngagement(engagement.id, { limit: 500 }),
        c.repos.hypotheses.listByEngagement(engagement.id, { limit: 500 }),
        c.repos.findings.listByEngagement(engagement.id, { limit: 200 }),
        c.repos.verifications.listByEngagement(engagement.id, 200),
        c.repos.budgets.getOrDefault(engagement.id, {}).then(async (limits) => ({
          limits: {
            max_model_calls: limits.max_model_calls,
            max_model_tokens: limits.max_model_tokens,
            max_network_requests: limits.max_network_requests,
            max_duration_seconds: limits.max_duration_seconds,
          },
          usage: await c.repos.budgets.getUsage(engagement.id),
        })),
        c.repos.agentRuns.findActiveByEngagement(engagement.id),
        c.repos.ctfContexts.findByEngagement(engagement.id),
        c.repos.ctfClues.listByEngagement(engagement.id),
        c.repos.flagConditions.listByEngagement(engagement.id),
      ]);

    const countBy = <T>(items: T[], key: (item: T) => string): Record<string, number> => {
      const out: Record<string, number> = {};
      for (const item of items) {
        const k = key(item);
        out[k] = (out[k] ?? 0) + 1;
      }
      return out;
    };

    return {
      engine: {
        engagement_id: engagement.id,
        phase: state.phase,
        is_terminal: ['COMPLETED', 'STOPPED', 'CANCELLED', 'FAILED'].includes(state.phase),
        mode: state.mode,
        waiting_reason: state.waiting_reason,
        strategy_summary: state.strategy_summary,
        replan_count: state.replan_count,
        cycle_count: state.cycle_count,
        last_replan_trigger: state.last_replan_trigger,
        stop_reason: state.stop_reason,
        engine_instance_id: state.engine_instance_id,
        started_at: state.started_at,
        finished_at: state.finished_at,
        last_transition_at: state.last_transition_at,
      },
      task_summary: countBy(tasks, (t) => t.status),
      hypothesis_summary: countBy(hypotheses, (h) => h.status),
      finding_summary: countBy(findings, (f) => f.status),
      verification_summary: countBy(verifications, (v) => v.status),
      budget,
      current_run: run ? { run_id: run.id, status: run.status, cycles: 0 } : null,
      ctf: ctfContext
        ? {
            status: ctfContext.status,
            clues_total: clues.length,
            flag_conditions_total: flagConditions.length,
          }
        : null,
    };
  });

  // ------------------------------------------------------------- graph (§12-§13)

  app.get('/api/engagements/:id/graph', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const graph = await engine().graph(engagement.id);
    return { graph };
  });

  // ------------------------------------------------------------- timeline (§53)

  app.get('/api/engagements/:id/timeline', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const query = (request.query ?? {}) as Record<string, string | undefined>;
    const limit = parseQueryInt(query.limit, c.config.autonomous.timelineLimit, 1, 500);
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const timeline = await engine().timelineView(engagement.id, limit);
    return { timeline };
  });

  // ------------------------------------------------------------- coverage (§51)

  app.get('/api/engagements/:id/coverage', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const coverage = await engine().coverage(engagement.id);
    return { coverage };
  });

  // ------------------------------------------------------------- tests (§60)

  app.get('/api/engagements/:id/tests', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const query = (request.query ?? {}) as Record<string, string | undefined>;
    const limit = parseQueryInt(query.limit, 200, 1, 500);
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const tests = await c.repos.tests.listByEngagement(engagement.id, limit);
    return {
      items: tests.map((test) => ({
        id: test.id,
        engagement_id: test.engagement_id,
        task_id: test.task_id,
        hypothesis_id: test.hypothesis_id,
        test_type: test.test_type,
        target: test.target,
        identity: test.identity,
        mutation_summary: test.mutation_summary,
        fingerprint: test.fingerprint,
        status: test.status,
        result: test.result,
        expected_signal: test.expected_signal,
        actual_signal: test.actual_signal,
        result_summary: test.result_summary,
        created_at: test.created_at,
      })),
      total: tests.length,
    };
  });

  // ------------------------------------------------------------- branches (§65)

  app.get('/api/engagements/:id/branches', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const branches = await c.repos.branches.listByEngagement(engagement.id);
    return {
      items: branches.map((branch) => ({
        id: branch.id,
        engagement_id: branch.engagement_id,
        parent_branch_id: branch.parent_branch_id,
        origin: branch.origin,
        origin_ref: branch.origin_ref,
        focus: branch.focus,
        hypothesis_ids: branch.hypothesis_ids,
        score: branch.score,
        status: branch.status,
        pruned_reason: branch.pruned_reason,
        created_at: branch.created_at,
        updated_at: branch.updated_at,
      })),
      total: branches.length,
    };
  });

  // ------------------------------------------------------------- verification queue (§26)

  app.get('/api/engagements/:id/verification-queue', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const queue = await engine().verificationQueue(engagement.id);
    return { items: queue, total: queue.length };
  });

  // ------------------------------------------------------------- approvals (§48)

  app.get('/api/engagements/:id/approvals', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const approvals = await c.repos.approvals.listByEngagement(engagement.id, { limit: 100 });
    return {
      items: approvals.map((approval) => ({
        id: approval.id,
        engagement_id: approval.engagement_id,
        task_id: approval.task_id,
        risk: approval.risk,
        action_summary: approval.action_summary,
        requested_by: approval.requested_by,
        decision: approval.decision,
        decided_by: approval.decided_by,
        decided_reason: approval.decided_reason,
        created_at: approval.created_at,
        decided_at: approval.decided_at,
      })),
      total: approvals.length,
    };
  });

  // ------------------------------------------------------------- human interventions (§48)

  app.post('/api/engagements/:id/prioritize', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(PrioritizeRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const ok = await engine().prioritizeHypothesis(engagement.id, body.hypothesis_id, body.note);
    if (!ok) {
      throw new ValidationError('Hypothesis not found for this engagement', 'HYPOTHESIS_NOT_FOUND');
    }
    return reply.send({ prioritized: true });
  });

  app.post('/api/engagements/:id/approve', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(ApproveRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const taskId = body.task_id ?? body.approval_id ?? null;
    if (!taskId) {
      throw new ValidationError('Provide task_id or approval_id to approve', 'APPROVAL_TARGET_REQUIRED');
    }
    const ok = await engine().approveTask(engagement.id, taskId, request.user.id, body.reason);
    if (!ok) {
      throw new ValidationError('Task is not waiting for approval', 'TASK_NOT_WAITING');
    }
    return reply.send({ approved: true });
  });

  app.post('/api/engagements/:id/reject', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(RejectRequestSchema, request.body ?? { reason: undefined });
    const approveBody = parseBody(ApproveRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const taskId = approveBody.task_id ?? approveBody.approval_id ?? null;
    if (!taskId) {
      throw new ValidationError('Provide task_id or approval_id to reject', 'APPROVAL_TARGET_REQUIRED');
    }
    const ok = await engine().rejectTask(engagement.id, taskId, request.user.id, body.reason);
    if (!ok) {
      throw new ValidationError('Task not found for this engagement', 'TASK_NOT_FOUND');
    }
    return reply.send({ rejected: true });
  });

  // ------------------------------------------------------------- CTF (§4, §29)

  app.post('/api/engagements/:id/ctf/context', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(UpsertCtfContextRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    if (engagement.mode !== 'CTF') {
      throw new ValidationError('CTF context is only valid for CTF-mode engagements', 'ENGAGEMENT_NOT_CTF');
    }
    const e = engine();
    if (!e.ctfEngine) {
      throw new NotImplementedError('CTF reasoning requires the knowledge engine (Part 5)', 'CTF_ENGINE_UNAVAILABLE');
    }
    await e.ctfEngine.initialize(engagement, {
      title: body.title,
      description: body.description,
      hints: body.hints,
      flagFormat: body.flag_format ?? null,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'CTF_CONTEXT_UPDATED',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
    });
    return reply.send({ updated: true });
  });

  app.post('/api/engagements/:id/ctf/clues', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(AddCtfClueRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const e = engine();
    if (!e.ctfEngine) {
      throw new NotImplementedError('CTF reasoning requires the knowledge engine (Part 5)', 'CTF_ENGINE_UNAVAILABLE');
    }
    await e.ctfEngine.addClue(engagement.id, body.text, body.source ?? 'USER');
    await e.ctfEngine.analyze(engagement.id);
    return reply.send({ added: true });
  });

  app.get('/api/engagements/:id/ctf', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const [context, clues, flagConditions] = await Promise.all([
      c.repos.ctfContexts.findByEngagement(engagement.id),
      c.repos.ctfClues.listByEngagement(engagement.id),
      c.repos.flagConditions.listByEngagement(engagement.id),
    ]);
    return {
      context: context
        ? {
            engagement_id: engagement.id,
            title: context.title,
            description: context.description,
            hints: context.hints,
            flag_format: context.flag_format,
            status: context.status,
            flag_value: context.flag_value,
            flag_evidence_id: context.flag_evidence_id,
            solved_at: context.solved_at,
          }
        : null,
      clues: clues.map((clue) => ({
        id: clue.id,
        engagement_id: clue.engagement_id,
        source: clue.source,
        text: clue.text_content,
        interpretations: clue.interpretations,
        branch_id: clue.branch_id,
        status: clue.status,
        dead_end_reason: clue.dead_end_reason,
        created_at: clue.created_at,
      })),
      flag_conditions: flagConditions.map((condition) => ({
        id: condition.id,
        engagement_id: condition.engagement_id,
        hypothesis_id: condition.hypothesis_id,
        condition_description: condition.condition_description,
        pattern: condition.pattern,
        evidence_ids: condition.evidence_ids,
        evidence_kinds: condition.evidence_kinds,
        detected_value: condition.detected_value,
        status: condition.status,
        detected_at: condition.detected_at,
        created_at: condition.created_at,
      })),
    };
  });

  // ------------------------------------------------------------- benchmarks (§79)

  app.get('/api/benchmarks', async () => {
    const { BENCHMARKS } = await import('@aegis/autonomous');
    return { items: BENCHMARKS };
  });

  app.get('/api/benchmarks/:name/runs', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { name } = request.params as { name: string };
    const runs = await c.repos.benchmarkRuns.listByBenchmark(name, 20);
    return {
      items: runs.map((run) => ({
        id: run.id,
        benchmark: run.benchmark,
        engagement_id: run.engagement_id,
        outcome: run.outcome,
        metrics: run.metrics,
        started_at: run.started_at,
        completed_at: run.completed_at,
      })),
    };
  });
}
