/**
 * Part 3 HTTP API routes (spec §19-§22, §41, §80).
 *
 * Human-level traffic inspection + controlled replay/mutation/HAR import.
 * These run through the same scope-validated engine + recorder pipeline
 * the worker tools use — no privileged bypass path.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  HttpRequestInputSchema,
  HttpReplayInputSchema,
  HttpMutateInputSchema,
  HarImportInputSchema,
} from '@aegis/contracts';
import { ScopeViolationError } from '@aegis/shared';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';
import { scopeRulesForEngagement } from '../lib/scope.js';

function requestRowToResponse(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    task_id: row.task_id,
    identity_id: row.identity_id,
    method: row.method,
    url: row.url,
    normalized_url: row.normalized_url,
    headers: row.headers,
    query: row.query,
    body: row.body_parsed !== null && row.body_parsed !== undefined
      ? {
          body_type: row.body_type,
          parsed: row.body_parsed,
          artifact_ref: row.body_artifact_ref,
          sha256: row.body_sha256,
          byte_length: row.body_bytes,
        }
      : null,
    source: row.source,
    provenance: {
      source: row.provenance_source,
      parent_task_id: row.provenance_parent_task_id,
      hypothesis_id: row.provenance_hypothesis_id,
      test_id: row.provenance_test_id,
      reason: row.provenance_reason,
    },
    parent_request_id: row.parent_request_id,
    browser_context_id: row.browser_context_id,
    created_at: (row.created_at as Date).toISOString(),
  };
}

function responseRowToResponse(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    request_id: row.request_id,
    status: row.status,
    headers: row.headers,
    content_type: row.content_type,
    content_kind: row.content_kind,
    body_artifact_ref: row.body_artifact_ref,
    body_sha256: row.body_sha256,
    content_length: row.content_length,
    truncated: row.truncated,
    timing_ms: row.timing_ms,
    redirect_to: row.redirect_to,
    created_at: (row.created_at as Date).toISOString(),
  };
}

export async function httpRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  // GET requests (paginated, engagement-scoped)
  app.get('/api/engagements/:id/http/requests', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { limit?: string; offset?: string };
    const limit = parseQueryInt(query.limit, 50, 1, 500);
    const offset = parseQueryInt(query.offset, 0, 0, 100_000);
    const rows = await c.repos.httpRequests.listByEngagement(id, limit, offset);
    const total = await c.repos.httpRequests.countByEngagement(id);
    return { items: rows.map(requestRowToResponse), total };
  });

  // GET one request + its response
  app.get('/api/engagements/:id/http/requests/:requestId', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, requestId } = request.params as { id: string; requestId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const row = await c.repos.httpRequests.findById(requestId);
    if (!row || row.engagement_id !== id) {
      return { request: null, response: null };
    }
    const response = await c.repos.httpResponses.findByRequestId(requestId);
    return {
      request: requestRowToResponse(row),
      response: response ? responseRowToResponse(response) : null,
    };
  });

  // POST direct request (tool path, API convenience)
  app.post('/api/engagements/:id/http/request', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    // Part 8 §89-90: emergency stop blocks all target-bound actions
    // deterministically (never via the model).
    if (c.hardening) {
      await c.hardening.emergencyStop.assertNotEngaged();
    }
    const body = parseBody(HttpRequestInputSchema, request.body ?? {});
    const scope = await scopeRulesForEngagement(c, engagement.id);
    if (!scope) {
      throw new ScopeViolationError('Engagement has no scope configured; requests are refused', 'SCOPE_NOT_CONFIGURED');
    }
    const result = await c.toolGateway.execute('http.request', body, {
      requestId: request.id,
      engagementId: engagement.id,
      identityId: body.identity_id ?? undefined,
      scope,
      permissions: { network: true, browser: c.config.features.toolsBrowser, destructive: scope.destructive_actions_allowed },
    });
    if (!result.ok) {
      return reply.code(502).send({ error: result.error });
    }
    await c.audit({
      actorUserId: request.user.id,
      action: 'HTTP_REQUEST_SENT',
      resource: 'http_request',
      engagementId: engagement.id,
      metadata: { url: body.url, method: body.method },
    });
    return result.output;
  });

  // POST replay (§19)
  app.post('/api/engagements/:id/http/replay', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    // Part 8 §89-90: emergency stop blocks all target-bound actions
    // deterministically (never via the model).
    if (c.hardening) {
      await c.hardening.emergencyStop.assertNotEngaged();
    }
    const body = parseBody(HttpReplayInputSchema, request.body ?? {});
    const scope = await scopeRulesForEngagement(c, engagement.id);
    if (!scope) {
      throw new ScopeViolationError('Engagement has no scope configured; replay is refused', 'SCOPE_NOT_CONFIGURED');
    }
    const result = await c.toolGateway.execute('http.replay', body, {
      requestId: request.id,
      engagementId: engagement.id,
      identityId: body.identity_id ?? undefined,
      scope,
      permissions: { network: true, browser: false, destructive: false },
    });
    if (!result.ok) {
      return reply.code(502).send({ error: result.error });
    }
    await c.audit({
      actorUserId: request.user.id,
      action: 'HTTP_REPLAY_EXECUTED',
      resource: 'http_request',
      resourceId: body.request_id,
      engagementId: engagement.id,
    });
    return result.output;
  });

  // POST mutate (§20-§22)
  app.post('/api/engagements/:id/http/mutate', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    // Part 8 §89-90: emergency stop blocks all target-bound actions
    // deterministically (never via the model).
    if (c.hardening) {
      await c.hardening.emergencyStop.assertNotEngaged();
    }
    const body = parseBody(HttpMutateInputSchema, request.body ?? {});
    const scope = await scopeRulesForEngagement(c, engagement.id);
    if (!scope) {
      throw new ScopeViolationError('Engagement has no scope configured; mutation is refused', 'SCOPE_NOT_CONFIGURED');
    }
    const result = await c.toolGateway.execute('http.mutate', body, {
      requestId: request.id,
      engagementId: engagement.id,
      identityId: body.identity_id ?? undefined,
      scope,
      permissions: { network: true, browser: false, destructive: false },
    });
    if (!result.ok) {
      return reply.code(502).send({ error: result.error });
    }
    await c.audit({
      actorUserId: request.user.id,
      action: 'HTTP_MUTATION_APPLIED',
      resource: 'http_request',
      resourceId: body.base_request_id,
      engagementId: engagement.id,
      metadata: { mutations: body.mutations.length },
    });
    return result.output;
  });

  // POST HAR import (§80)
  app.post('/api/engagements/:id/http/har-import', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(HarImportInputSchema, request.body ?? {});
    const scope = await scopeRulesForEngagement(c, engagement.id);
    if (!scope) {
      throw new ScopeViolationError('Engagement has no scope configured; import is refused', 'SCOPE_NOT_CONFIGURED');
    }
    const result = await c.toolGateway.execute('har.import', body, {
      requestId: request.id,
      engagementId: engagement.id,
      scope,
      permissions: { network: true, browser: false, destructive: false },
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'HAR_IMPORTED',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { imported: result.ok ? (result.output as { imported: number }).imported : 0 },
    });
    return result.ok ? result.output : { error: result.error };
  });

  // GET tool executions (§78 reproducibility log)
  app.get('/api/engagements/:id/tool-executions', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { limit?: string };
    const limit = parseQueryInt(query.limit, 100, 1, 1000);
    const rows = await c.repos.toolExecutions.listByEngagement(id, limit);
    return {
      items: rows.map((row) => ({
        ...row,
        created_at: (row.created_at as Date).toISOString(),
      })),
      total: rows.length,
    };
  });
}

