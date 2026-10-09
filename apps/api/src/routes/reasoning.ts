/**
 * Security reasoning API routes (spec Part 4 §108, §118, §120).
 *
 * Human and programmatic inspection of the deterministic reasoning layer:
 *  - status + ingestion (backfill over recorded traffic)
 *  - attack surface: endpoints, parameters, authorization matrix, objects,
 *    workflows (+detail), data flows, attack graph
 *  - signals + deterministic hypothesis candidates (§44-§45)
 *  - test candidates (§118 — the Part 2 scheduler seam, read-only here)
 *  - differential comparison (§25) + records
 *  - verification evaluation (§72) + records
 *  - focused query (§80) and leader projection (§120)
 *
 * Mutating endpoints (ingest/compare/verify/consume) are audited. When the
 * reasoning engine is disabled by configuration the routes answer 501 —
 * honest unavailability, never silent pretense.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  DifferentialCompareInputSchema,
  ReasoningQueryInputSchema,
  VerificationEvaluateInputSchema,
} from '@aegis/contracts';
import { NotImplementedError, NotFoundError, ValidationError } from '@aegis/shared';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';
import type { AppContext } from '../context.js';
import type { SecurityReasoningEngine } from '@aegis/reasoning';

function requireReasoning(c: AppContext): SecurityReasoningEngine {
  if (!c.reasoning) {
    throw new NotImplementedError(
      'The security reasoning engine is disabled for this deployment (FEATURE_SECURITY_REASONING=false)',
      'SECURITY_REASONING_DISABLED',
    );
  }
  return c.reasoning;
}

export async function reasoningRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  // ------------------------------------------------------------- status

  app.get('/api/engagements/:id/reasoning/status', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    return requireReasoning(c).status(id);
  });

  // ------------------------------------------------------------- ingest

  app.post('/api/engagements/:id/reasoning/ingest', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(z.object({ limit: z.number().int().min(1).max(1000).optional() }), request.body ?? {});
    const summary = await requireReasoning(c).ingest(id, body.limit ?? 200);
    await c.audit({
      actorUserId: request.user.id,
      action: 'REASONING_INGEST',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { ...summary },
    });
    reply.code(200);
    return {
      processed: summary.processed,
      created_endpoints: summary.createdEndpoints,
      updated_endpoints: summary.updatedEndpoints,
      created_parameters: summary.createdParameters,
      matrix_entries: summary.matrixEntries,
      signals_created: summary.signalsCreated,
      failures: summary.failures,
    };
  });

  // -------------------------------------------------- attack surface reads

  app.get('/api/engagements/:id/reasoning/endpoints', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 100, 1, 500);
    const items = await c.repos.endpoints.listByEngagement(id, { limit });
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/parameters', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 200, 1, 1000);
    const items = await c.repos.parameters.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/signals', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 100, 1, 500);
    const query = request.query as { status?: string };
    const statuses = query.status
      ? (query.status.split(',').filter((s) => ['NEW', 'CONSUMED', 'SUPERSEDED'].includes(s)) as Array<'NEW' | 'CONSUMED' | 'SUPERSEDED'>)
      : undefined;
    const items = await c.repos.securitySignals.listByEngagement(id, { statuses, limit });
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/authorization-matrix', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 500, 1, 1000);
    const items = await c.repos.authzMatrix.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/objects', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 100, 1, 200);
    const items = await c.repos.objectCandidates.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/workflows', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const items = await c.repos.workflows.listByEngagement(id);
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/workflows/:workflowId', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, workflowId } = request.params as { id: string; workflowId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const workflow = await c.repos.workflows.findById(workflowId);
    if (!workflow || workflow.engagement_id !== id) {
      throw new NotFoundError('WORKFLOW');
    }
    const [states, transitions] = await Promise.all([
      c.repos.workflowStates.listByWorkflow(workflowId),
      c.repos.workflowTransitions.listByWorkflow(workflowId),
    ]);
    return { workflow, states, transitions };
  });

  app.get('/api/engagements/:id/reasoning/data-flows', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 200, 1, 500);
    const items = await c.repos.dataFlows.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.get('/api/engagements/:id/reasoning/graph', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 500, 1, 2000);
    const [nodes, edges] = await Promise.all([
      c.repos.attackNodes.listByEngagement(id, { limit }),
      c.repos.attackEdges.listByEngagement(id, limit * 2),
    ]);
    return { nodes, edges };
  });

  // ------------------------------------------------- hypothesis candidates

  app.get('/api/engagements/:id/reasoning/hypotheses/candidates', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const groups = await requireReasoning(c).hypothesisCandidates(id);
    return {
      groups: groups.map((group) => ({
        signal_id: group.signalId,
        signal_type: group.signalType,
        primary: group.primary,
        competitors: group.competitors,
        distinguishing_tests: group.distinguishingTests,
      })),
      total: groups.reduce((sum, group) => sum + 1 + group.competitors.length, 0),
    };
  });

  app.post('/api/engagements/:id/reasoning/hypotheses/candidates/consume', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(
      z.object({ signal_ids: z.array(z.string()).min(1).max(64) }),
      request.body ?? {},
    );
    // Only consume signals that actually belong to this engagement.
    const owned = await c.repos.securitySignals.listByEngagement(id, { limit: 500 });
    const ownedIds = new Set(owned.map((signal) => signal.id));
    const validIds = body.signal_ids.filter((signalId: string) => ownedIds.has(signalId));
    if (validIds.length === 0) {
      throw new ValidationError('No matching signals for this engagement', 'SIGNALS_NOT_FOUND');
    }
    await requireReasoning(c).markSignalsConsumed(validIds);
    await c.audit({
      actorUserId: request.user.id,
      action: 'REASONING_SIGNALS_CONSUMED',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { consumed: validIds.length },
    });
    return { consumed: validIds.length, skipped: body.signal_ids.length - validIds.length };
  });

  // ------------------------------------------------------- test candidates

  app.get('/api/engagements/:id/reasoning/test-candidates', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    return requireReasoning(c).testCandidates(id);
  });

  // -------------------------------------------------------- differentials

  app.get('/api/engagements/:id/reasoning/differentials', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 50, 1, 200);
    const items = await c.repos.differentialResults.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.post('/api/engagements/:id/reasoning/differential', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(DifferentialCompareInputSchema, request.body ?? {});
    const result = await requireReasoning(c).compareDifferential({
      engagementId: engagement.id,
      baselineRequestId: body.baseline_request_id,
      candidateRequestId: body.candidate_request_id,
      hypothesisId: body.hypothesis_id,
      testId: body.test_id,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'REASONING_DIFFERENTIAL',
      resource: 'differential',
      resourceId: result.recordId,
      engagementId: engagement.id,
      metadata: {
        status_changed: result.summary.status_changed,
        schema_changed: result.summary.schema_changed,
        body_similarity: result.summary.body_similarity,
      },
    });
    reply.code(201);
    return { id: result.recordId, summary: result.summary };
  });

  // -------------------------------------------------------- verifications

  app.get('/api/engagements/:id/reasoning/verifications', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as { limit?: string }).limit, 50, 1, 200);
    const items = await c.repos.verifications.listByEngagement(id, limit);
    return { items, total: items.length };
  });

  app.post('/api/engagements/:id/reasoning/verify', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(VerificationEvaluateInputSchema, request.body ?? {});
    const result = await requireReasoning(c).evaluateWithBridge({
      engagementId: engagement.id,
      hypothesisId: body.hypothesis_id,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'REASONING_VERIFICATION',
      resource: 'verification',
      resourceId: result.verification.id,
      engagementId: engagement.id,
      metadata: { hypothesis_id: body.hypothesis_id, status: result.verification.status },
    });
    reply.code(201);
    const { outcome, ...response } = result;
    return { ...response, outcome: { status: outcome.status, kind: outcome.kind, alternatives: outcome.alternatives } };
  });

  // ------------------------------------------- focused query + projection

  app.post('/api/engagements/:id/reasoning/query', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(ReasoningQueryInputSchema, request.body ?? {});
    return requireReasoning(c).query({
      engagementId: id,
      endpointId: body.endpoint_id,
      hypothesisId: body.hypothesis_id,
      signalType: body.signal_type,
    });
  });

  app.get('/api/engagements/:id/reasoning/projection', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    return requireReasoning(c).buildSecurityProjection(id);
  });
}
