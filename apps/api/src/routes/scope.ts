/** Scope routes: configure and read the engagement scope (spec §27). */
import type { FastifyInstance } from 'fastify';
import { ScopeRequestSchema, ScopeResponseSchema, ScopeSchema } from '@aegis/contracts';
import { ValidationError, generateId } from '@aegis/shared';
import type { ScopeRecord } from '@aegis/database';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

export function toScopeResponse(scope: ScopeRecord) {
  return ScopeSchema.parse({
    id: scope.id,
    engagement_id: scope.engagement_id,
    allowed_hosts: scope.allowed_hosts,
    allowed_domains: scope.allowed_domains,
    allowed_ports: scope.allowed_ports,
    allowed_schemes: scope.allowed_schemes,
    excluded_hosts: scope.excluded_hosts,
    excluded_paths: scope.excluded_paths,
    rate_limit: scope.rate_limit,
    concurrency_limit: scope.concurrency_limit,
    destructive_actions_allowed: scope.destructive_actions_allowed,
    created_at: scope.created_at,
    updated_at: scope.updated_at,
  });
}

/** Scope is configurable while the engagement is not actively running. */
const EDITABLE_STATUSES = new Set(['DRAFT', 'READY', 'PAUSED']);

export async function scopeRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/engagements/:id/scope', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const scope = await c.repos.scope.findByEngagement(id);
    return ScopeResponseSchema.parse({ scope: scope ? toScopeResponse(scope) : null });
  });

  app.post('/api/engagements/:id/scope', async (request) => {
    const body = parseBody(ScopeRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);

    if (!EDITABLE_STATUSES.has(engagement.status)) {
      throw new ValidationError(
        `Scope cannot be changed while the engagement is ${engagement.status}; pause or cancel it first`,
        'SCOPE_IMMUTABLE_WHILE_RUNNING',
        { status: engagement.status },
      );
    }

    const scope = await c.repos.scope.upsert(id, {
      allowed_hosts: body.allowed_hosts.map((h) => h.toLowerCase()),
      allowed_domains: body.allowed_domains.map((d) => d.toLowerCase()),
      allowed_ports: body.allowed_ports,
      allowed_schemes: body.allowed_schemes,
      excluded_hosts: body.excluded_hosts.map((h) => h.toLowerCase()),
      excluded_paths: body.excluded_paths,
      rate_limit: body.rate_limit ?? null,
      concurrency_limit: body.concurrency_limit ?? null,
      destructive_actions_allowed: body.destructive_actions_allowed,
    });

    await c.eventBus.publish({
      type: 'SCOPE_UPDATED',
      engagement_id: id,
      trace_id: generateId('TRC'),
      actor_id: request.user.id,
      payload: {
        allowed_hosts: scope.allowed_hosts.length,
        allowed_domains: scope.allowed_domains.length,
        allowed_schemes: scope.allowed_schemes,
      },
      occurred_at: new Date().toISOString(),
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'SCOPE_CHANGED',
      resource: 'scope',
      resourceId: scope.id,
      engagementId: id,
      metadata: {
        allowed_hosts: scope.allowed_hosts,
        allowed_domains: scope.allowed_domains,
        allowed_schemes: scope.allowed_schemes,
        destructive_actions_allowed: scope.destructive_actions_allowed,
      },
    });

    // DRAFT -> READY promotion when preconditions now hold.
    await c.orchestrator.markReadyIfEligible(engagement, request.user.id);

    return toScopeResponse(scope);
  });
}
