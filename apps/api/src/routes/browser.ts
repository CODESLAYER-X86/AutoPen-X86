/**
 * Part 3 browser API routes (spec §3-§10, §23-§39, §73-§75).
 *
 * Human-level control + inspection of the isolated browser layer:
 *  - contexts (open per identity / list / close) — §3-§6
 *  - structured actions (§7-§8) — same service path the worker tools use
 *  - event stream, DOM snapshots, diff, cookies (redacted), storage (§11, §23-§24, §32-§33)
 *  - downloads, WebSocket observations (§36-§37)
 *  - capture-state + promote-session (§28: login workflow -> reusable session)
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { ScopeViolationError } from '@aegis/shared';
import { BrowserActionRequestSchema } from '@aegis/contracts';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';
import { requireScopeForEngagement } from '../lib/scope.js';

const OpenContextSchema = z.object({
  identity_id: z.string().nullable().default(null),
});

const RegisterSessionSchema = z.object({
  identity_id: z.string(),
  kind: z.enum(['COOKIE', 'BEARER', 'JWT', 'API_KEY', 'CUSTOM_HEADER', 'BROWSER_STORAGE']),
  cookies: z
    .array(
      z.object({
        name: z.string().min(1).max(256),
        value: z.string().max(4096),
        domain: z.string().min(1).max(253),
        path: z.string().max(1024).default('/'),
        secure: z.boolean().default(false),
        http_only: z.boolean().default(false),
        same_site: z.enum(['Strict', 'Lax', 'None']).nullable().default(null),
        expires: z.number().nullable().default(null),
      }),
    )
    .max(64)
    .optional(),
  token: z.string().max(8192).optional(),
  headers: z.array(z.object({ name: z.string().min(1).max(128), value: z.string().max(8192) })).max(16).optional(),
  storage: z
    .array(
      z.object({
        origin: z.string().min(1).max(2048),
        area: z.enum(['LOCAL', 'SESSION']),
        key: z.string().min(1).max(512),
        value: z.string().max(8192),
      }),
    )
    .max(64)
    .optional(),
  expires_at: z.string().nullable().default(null),
  workflow: z
    .object({
      steps: z
        .array(z.object({ action: z.string().max(128), detail: z.string().max(1024), success: z.boolean() }))
        .max(64),
      evidence_ids: z.array(z.string()).max(64).optional(),
    })
    .nullable()
    .default(null),
});

export async function browserRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  // POST open a context for an identity (§3-§4) — anonymous allowed (§30).
  app.post('/api/engagements/:id/browser/contexts', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(OpenContextSchema, request.body ?? {});
    await requireScopeForEngagement(c, engagement.id);

    if (body.identity_id) {
      const identity = await c.repos.identities.findById(body.identity_id);
      if (!identity || identity.engagement_id !== engagement.id) {
        throw new ScopeViolationError('Identity not found in this engagement', 'IDENTITY_NOT_IN_ENGAGEMENT');
      }
    }

    const handle = await c.browserService.getContextHandle(engagement.id, body.identity_id);
    await c.audit({
      actorUserId: request.user.id,
      action: 'BROWSER_CONTEXT_CREATED',
      resource: 'browser_context',
      resourceId: handle.id,
      engagementId: engagement.id,
      metadata: { identity_id: body.identity_id },
    });
    return { context_id: handle.id, identity_id: body.identity_id, status: handle.status };
  });

  // GET contexts
  app.get('/api/engagements/:id/browser/contexts', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const rows = await c.repos.browserContexts.listByEngagement(id);
    return {
      items: rows.map((row) => ({ ...row, created_at: (row.created_at as Date).toISOString() })),
      total: rows.length,
    };
  });

  // POST close a context (§75 cleanup)
  app.post('/api/engagements/:id/browser/contexts/:contextId/close', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, contextId } = request.params as { id: string; contextId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    await c.browserService.closeContext(id, contextId);
    await c.audit({
      actorUserId: request.user.id,
      action: 'BROWSER_CONTEXT_CLOSED',
      resource: 'browser_context',
      resourceId: contextId,
      engagementId: id,
    });
    return { context_id: contextId, status: 'CLOSED' };
  });

  // POST structured browser action (§7-§8) — gateway path.
  app.post('/api/engagements/:id/browser/actions', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(BrowserActionRequestSchema, request.body ?? {});
    const scope = await requireScopeForEngagement(c, engagement.id);

    const toolName = `browser.${body.action}`;
    const result = await c.toolGateway.execute(toolName, body, {
      requestId: request.id,
      engagementId: engagement.id,
      identityId: undefined,
      scope,
      permissions: { network: true, browser: true, destructive: false },
    });
    if (!result.ok) {
      return reply.code(502).send({ error: result.error });
    }
    await c.audit({
      actorUserId: request.user.id,
      action: 'BROWSER_ACTION',
      resource: 'browser_context',
      resourceId: body.context_id,
      engagementId: engagement.id,
      metadata: { action: body.action },
    });
    return result.output;
  });

  // GET browser events (§11)
  app.get('/api/engagements/:id/browser/events', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { limit?: string; context_id?: string };
    const limit = parseQueryInt(query.limit, 200, 1, 2000);
    const rows = query.context_id
      ? await c.repos.browserEvents.listByContext(query.context_id, limit)
      : await c.repos.browserEvents.listByEngagement(id, limit);
    return {
      items: rows.map((row) => ({ ...row, occurred_at: (row.occurred_at as Date).toISOString() })),
      total: rows.length,
    };
  });

  // GET DOM snapshots (§32)
  app.get('/api/engagements/:id/browser/snapshots', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { limit?: string };
    const limit = parseQueryInt(query.limit, 50, 1, 500);
    const rows = await c.repos.domSnapshots.listByEngagement(id, limit);
    return {
      items: rows.map((row) => ({
        id: row.id,
        context_id: row.context_id,
        page_id: row.page_id,
        url: row.url,
        title: row.title,
        evidence_id: row.evidence_id,
        created_at: (row.created_at as Date).toISOString(),
      })),
      total: rows.length,
    };
  });

  // GET cookies (redacted — §23)
  app.get('/api/engagements/:id/browser/cookies', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { context_id?: string };
    const rows = query.context_id
      ? await c.repos.cookies.listByContext(query.context_id)
      : await c.repos.cookies.listByEngagement(id);
    return { items: rows.map((row) => ({ ...row, created_at: (row.created_at as Date).toISOString() })), total: rows.length };
  });

  // GET storage entries (§24)
  app.get('/api/engagements/:id/browser/storage', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { context_id?: string };
    if (!query.context_id) {
      return { items: [], total: 0 };
    }
    const rows = await c.repos.storageEntries.listByContext(query.context_id);
    return { items: rows.map((row) => ({ ...row, created_at: (row.created_at as Date).toISOString() })), total: rows.length };
  });

  // POST capture state (cookies + storage into secret store)
  app.post('/api/engagements/:id/browser/contexts/:contextId/capture-state', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, contextId } = request.params as { id: string; contextId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const state = await c.browserService.captureContextState(id, contextId);
    await c.audit({
      actorUserId: request.user.id,
      action: 'BROWSER_STATE_CAPTURED',
      resource: 'browser_context',
      resourceId: contextId,
      engagementId: id,
    });
    return state;
  });

  // POST promote context state to an identity session (§28)
  app.post('/api/engagements/:id/browser/contexts/:contextId/promote-session', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id, contextId } = request.params as { id: string; contextId: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const body = parseBody(RegisterSessionSchema, request.body ?? {});

    const contexts = await c.repos.browserContexts.listByEngagement(id);
    const context = contexts.find((row) => row.id === contextId);
    if (!context) {
      throw new ScopeViolationError('Browser context not found in this engagement', 'CONTEXT_NOT_FOUND');
    }
    const identityId = (context.identity_id as string | null) ?? body.identity_id;
    if (!identityId) {
      throw new ScopeViolationError('Context has no identity and none was provided', 'IDENTITY_REQUIRED');
    }
    const identity = await c.repos.identities.findById(identityId);
    if (!identity || identity.engagement_id !== id) {
      throw new ScopeViolationError('Identity not found in this engagement', 'IDENTITY_NOT_IN_ENGAGEMENT');
    }

    // Session material flows operator -> secret store -> session manager;
    // values never transit model context and are never echoed in responses.
    const session = await c.sessionManager.registerAuthState({
      engagementId: engagement.id,
      identityId,
      material: {
        kind: body.kind,
        cookies: body.cookies?.map((cookie) => ({
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain,
          path: cookie.path,
          secure: cookie.secure,
          httpOnly: cookie.http_only,
          sameSite: cookie.same_site,
          expires: cookie.expires,
        })),
        token: body.token,
        headers: body.headers,
        storage: body.storage,
      },
      expiresAt: body.expires_at ? new Date(body.expires_at) : null,
      workflow: body.workflow
        ? { steps: body.workflow.steps, evidenceIds: body.workflow.evidence_ids ?? [] }
        : null,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'AUTH_WORKFLOW_RECORDED',
      resource: 'session',
      resourceId: session.id,
      engagementId: engagement.id,
      metadata: { identity_id: identityId, kind: body.kind },
    });
    return {
      session_id: session.id,
      identity_id: identityId,
      kind: body.kind,
      status: session.status,
    };
  });

  // GET downloads (§37)
  app.get('/api/engagements/:id/browser/downloads', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const rows = await c.repos.downloads.listByEngagement(id);
    return { items: rows.map((row) => ({ ...row, created_at: (row.created_at as Date).toISOString() })), total: rows.length };
  });

  // GET WebSocket connections + messages (§36)
  app.get('/api/engagements/:id/browser/websockets', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const query = request.query as { connection_id?: string; limit?: string };
    const limit = parseQueryInt(query.limit, 100, 1, 1000);
    const connections = await c.repos.websockets.listConnections(id);
    const filtered = query.connection_id
      ? connections.filter((conn) => conn.id === query.connection_id)
      : connections;
    const items = [];
    for (const connection of filtered) {
      const messages = await c.repos.websockets.listMessages(connection.id as string, limit);
      items.push({
        ...connection,
        opened_at: (connection.opened_at as Date).toISOString(),
        messages: messages.map((m) => ({ ...m, created_at: (m.created_at as Date).toISOString() })),
      });
    }
    return { items, total: items.length };
  });

  // GET auth workflows (§28)
  app.get('/api/engagements/:id/auth-workflows', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Code();
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const rows = await c.repos.authWorkflows.listByEngagement(id);
    return {
      items: rows.map((row) => ({ ...row, created_at: (row.created_at as Date).toISOString() })),
      total: rows.length,
    };
  });
}

class Code extends ScopeViolationError {
  constructor() {
    super('auth invariant violated', 'AUTH_REQUIRED');
  }
}
