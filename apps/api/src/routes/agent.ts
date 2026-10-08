/**
 * Agent OS API routes (spec Part 2 §45-§46, §58).
 *
 * Human inspection and intervention over the autonomous system:
 *  - agent runs (start/pause/resume/cancel/list/get)
 *  - tasks, hypotheses, observations, dead ends, strategies, findings
 *  - agent metrics (§58 observability)
 *  - human overrides (§46): add CTF clue, prioritize hypothesis, cancel task,
 *    request verification, pause run — all audited
 *  - crash recovery trigger (§63-§64)
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  HumanOverrideSchema,
  StartAgentRunRequestSchema,
} from '@aegis/contracts';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

function toRunResponse(run: {
  id: string;
  engagement_id: string;
  status: string;
  reason: string | null;
  strategy_version: number | null;
  leader_model: string;
  worker_model: string;
  metrics: Record<string, unknown>;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
  updated_at: string;
}) {
  return { ...run };
}

function toTaskResponse(task: {
  id: string;
  engagement_id: string;
  run_id: string | null;
  hypothesis_id: string | null;
  type: string;
  objective: string;
  worker_type: string;
  status: string;
  priority: number;
  depends_on: string[];
  allowed_tools: string[];
  constraints: Record<string, unknown>;
  attempts: number;
  max_attempts: number;
  failure_code: string | null;
  failure_reason: string | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
}) {
  return { ...task };
}

export async function agentRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  // ----------------------------------------------------------------- runs

  app.post('/api/engagements/:id/runs', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = parseBody(StartAgentRunRequestSchema, request.body ?? {});
    const engagement = await requireOwnedEngagement(c, request.user.id, id);

    const run = await c.agentEngines.startRun(engagement, request.user.id, body.reason);
    await c.audit({
      actorUserId: request.user.id,
      action: 'AGENT_RUN_STARTED',
      resource: 'agent_run',
      resourceId: run.runId,
      engagementId: engagement.id,
      metadata: { reason: body.reason ?? null },
    });
    const record = await c.repos.agentRuns.findById(run.runId);
    reply.code(201);
    return toRunResponse(record!);
  });

  app.get('/api/engagements/:id/runs', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 50, 1, 200);
    const runs = await c.repos.agentRuns.listByEngagement(id, limit);
    return { items: runs.map(toRunResponse), total: runs.length };
  });

  app.post('/api/engagements/:id/runs/:runId/pause', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string; runId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    await c.agentEngines.pause(id, request.user.id, 'operator pause via API');
    await c.audit({
      actorUserId: request.user.id,
      action: 'AGENT_RUN_PAUSED',
      resource: 'agent_run',
      resourceId: null,
      engagementId: id,
      metadata: {},
    });
    const run = await c.repos.agentRuns.findActiveByEngagement(id);
    return { paused: true, run: run ? toRunResponse(run) : null };
  });

  app.post('/api/engagements/:id/runs/:runId/resume', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string; runId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    await c.agentEngines.resume(id, request.user.id);
    await c.audit({
      actorUserId: request.user.id,
      action: 'AGENT_RUN_RESUMED',
      resource: 'agent_run',
      resourceId: null,
      engagementId: id,
      metadata: {},
    });
    const run = await c.repos.agentRuns.findActiveByEngagement(id);
    return { resumed: true, run: run ? toRunResponse(run) : null };
  });

  app.post('/api/engagements/:id/runs/:runId/cancel', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string; runId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    await c.agentEngines.cancel(id, request.user.id, 'operator cancellation via API');
    await c.audit({
      actorUserId: request.user.id,
      action: 'AGENT_RUN_CANCELLED',
      resource: 'agent_run',
      resourceId: null,
      engagementId: id,
      metadata: {},
    });
    return { cancelled: true };
  });

  // ---------------------------------------------------------------- tasks

  app.get('/api/engagements/:id/tasks', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { status?: string; limit?: string };
    const limit = parseQueryInt(query.limit, 100, 1, 500);
    const tasks = await c.repos.tasks.listByEngagement(id, {
      ...(query.status
        ? { statuses: [query.status as 'READY'] }
        : {}),
      limit,
    });
    return { items: tasks.map(toTaskResponse), total: tasks.length };
  });

  app.post('/api/engagements/:id/tasks/:taskId/cancel', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, taskId } = request.params as { id: string; taskId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const result = await c.agentEngines.applyHumanOverride({
      engagementId: id,
      actorId: request.user.id,
      kind: 'CANCEL_TASK',
      payload: { task_id: taskId, reason: 'operator cancellation via API' },
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'TASK_CANCELLED',
      resource: 'task',
      resourceId: taskId,
      engagementId: id,
      metadata: result,
    });
    return result;
  });

  // --------------------------------------------------------- hypotheses

  app.get('/api/engagements/:id/hypotheses', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 200, 1, 500);
    const hypotheses = await c.repos.hypotheses.listByEngagement(id, { limit });
    return { items: hypotheses.map((h) => ({ ...h })), total: hypotheses.length };
  });

  // ------------------------------------------------- dead ends / strategies

  app.get('/api/engagements/:id/dead-ends', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const deadEnds = await c.repos.deadEnds.listByEngagement(id, 100);
    return { items: deadEnds.map((d) => ({ ...d })), total: deadEnds.length };
  });

  app.get('/api/engagements/:id/strategies', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const strategies = await c.repos.strategies.listByEngagement(id, 50);
    return { items: strategies.map((s) => ({ ...s })), total: strategies.length };
  });

  // ---------------------------------------------------- observations / findings

  app.get('/api/engagements/:id/observations', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 50, 1, 200);
    const observations = await c.repos.observations.listByEngagement(id, limit);
    return { items: observations.map((o) => ({ ...o })), total: observations.length };
  });

  app.get('/api/engagements/:id/findings', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const findings = await c.repos.findings.listByEngagement(id, {});
    return { items: findings.map((f) => ({ ...f })), total: findings.length };
  });

  // ------------------------------------------------------------ metrics

  app.get('/api/engagements/:id/agent-metrics', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const metrics = await c.agentEngines.metrics(id);
    return { engagement_id: id, ...metrics };
  });

  // ---------------------------------------------------- human overrides (§46)

  app.post('/api/engagements/:id/overrides', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const override = parseBody(HumanOverrideSchema, request.body);

    const payload: Record<string, unknown> = {};
    if (override.kind === 'ADD_CTF_CLUE') payload.clue = override.clue;
    if (override.kind === 'PRIORITIZE_HYPOTHESIS') {
      payload.hypothesis_id = override.hypothesis_id;
      payload.priority = override.priority;
      if (override.reason) payload.reason = override.reason;
    }
    if (override.kind === 'CANCEL_TASK') {
      payload.task_id = override.task_id;
      if (override.reason) payload.reason = override.reason;
    }
    if (override.kind === 'REQUEST_VERIFICATION') {
      payload.hypothesis_id = override.hypothesis_id;
      if (override.reason) payload.reason = override.reason;
    }
    if (override.kind === 'PAUSE_RUN' && override.reason) payload.reason = override.reason;

    const result = await c.agentEngines.applyHumanOverride({
      engagementId: id,
      actorId: request.user.id,
      kind: override.kind,
      payload,
    });

    await c.audit({
      actorUserId: request.user.id,
      action: `HUMAN_OVERRIDE_${override.kind}`,
      resource: 'engagement',
      resourceId: id,
      engagementId: id,
      metadata: { kind: override.kind, ...result },
    });
    return { kind: override.kind, ...result };
  });

  // ------------------------------------------------------- crash recovery

  app.post('/api/engagements/:id/recovery', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const report = await c.agentEngines.recover(id);
    await c.audit({
      actorUserId: request.user.id,
      action: 'AGENT_RECOVERY_RUN',
      resource: 'engagement',
      resourceId: id,
      engagementId: id,
      metadata: report,
    });
    return report;
  });
}
