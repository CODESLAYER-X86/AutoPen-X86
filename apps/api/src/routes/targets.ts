/**
 * Target routes. Every target is validated against the engagement scope
 * BEFORE insertion — an out-of-scope target never reaches the database
 * and the attempt is audited (spec §11, §33).
 */
import type { FastifyInstance } from 'fastify';
import { CreateTargetRequestSchema, TargetSchema } from '@aegis/contracts';
import {
  ScopeViolationError,
  ValidationError,
  generateId,
} from '@aegis/shared';
import type { TargetRecord } from '@aegis/database';
import { ScopeChecker, validateTargetAgainstScope } from '@aegis/security';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

const EDITABLE_STATUSES = new Set(['DRAFT', 'READY', 'PAUSED']);

export function toTargetResponse(target: TargetRecord) {
  return TargetSchema.parse({
    id: target.id,
    engagement_id: target.engagement_id,
    type: target.type,
    value: target.value,
    label: target.label,
    metadata: target.metadata,
    created_at: target.created_at,
    updated_at: target.updated_at,
  });
}

export async function targetRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/engagements/:id/targets', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const targets = await c.repos.targets.listByEngagement(id);
    return { items: targets.map(toTargetResponse), total: targets.length };
  });

  app.post('/api/engagements/:id/targets', async (request, reply) => {
    const body = parseBody(CreateTargetRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);

    if (!EDITABLE_STATUSES.has(engagement.status)) {
      throw new ValidationError(
        `Targets cannot be added while the engagement is ${engagement.status}; pause or cancel it first`,
        'TARGETS_IMMUTABLE_WHILE_RUNNING',
        { status: engagement.status },
      );
    }

    const scope = await c.repos.scope.findByEngagement(id);
    if (!scope) {
      throw new ScopeViolationError(
        'No scope is configured for this engagement; configure the scope before adding targets',
        'SCOPE_NOT_CONFIGURED',
      );
    }

    const rules = {
      allowed_hosts: scope.allowed_hosts,
      allowed_domains: scope.allowed_domains,
      allowed_ports: scope.allowed_ports,
      allowed_schemes: scope.allowed_schemes,
      excluded_hosts: scope.excluded_hosts,
      excluded_paths: scope.excluded_paths,
      rate_limit: scope.rate_limit,
      concurrency_limit: scope.concurrency_limit,
      destructive_actions_allowed: scope.destructive_actions_allowed,
    };

    // Deterministic scope validation — never delegated to a model.
    const verdict = validateTargetAgainstScope(body.type, body.value, rules);
    if (!verdict.allowed) {
      await c.eventBus.publish({
        type: 'TARGET_REJECTED',
        engagement_id: id,
        trace_id: generateId('TRC'),
        actor_id: request.user.id,
        payload: {
          type: body.type,
          value: body.value.slice(0, 256),
          code: verdict.code,
          reason: verdict.reason,
        },
        occurred_at: new Date().toISOString(),
      });
      await c.audit({
        actorUserId: request.user.id,
        action: 'TARGET_REJECTED',
        resource: 'engagement',
        resourceId: id,
        engagementId: id,
        metadata: { type: body.type, code: verdict.code, reason: verdict.reason },
      });
      throw new ScopeViolationError(
        `Target rejected by scope validation: ${verdict.reason}`,
        'TARGET_OUT_OF_SCOPE',
        { code: verdict.code, target_type: body.type },
      );
    }

    // Normalise URL targets using the scope checker's parsing.
    let normalizedValue = body.value.trim();
    if (body.type === 'URL' || body.type === 'CTF_INSTANCE' || body.type === 'APPLICATION') {
      const check = new ScopeChecker(rules).checkUrl(normalizedValue);
      if (check.allowed) {
        normalizedValue = `${check.normalized.scheme}://${check.normalized.host}${check.normalized.port !== null && !isDefaultPort(check.normalized.scheme, check.normalized.port) ? `:${check.normalized.port}` : ''}${check.normalized.path}`;
      }
    }

    let target: TargetRecord;
    try {
      target = await c.repos.targets.create({
        engagementId: id,
        type: body.type,
        value: normalizedValue,
        label: body.label ?? null,
        metadata: verdict.allowed ? { scope_check: 'passed' } : {},
      });
    } catch (error) {
      const duplicate =
        (error as { code?: string }).code === '23505' ||
        ((error as { message?: string }).message ?? '').includes('duplicate key');
      if (duplicate) {
        throw new ValidationError(
          'This exact target already exists in the engagement',
          'TARGET_ALREADY_EXISTS',
        );
      }
      throw error;
    }

    await c.eventBus.publish({
      type: 'TARGET_ADDED',
      engagement_id: id,
      trace_id: generateId('TRC'),
      actor_id: request.user.id,
      payload: { target_id: target.id, type: target.type },
      occurred_at: new Date().toISOString(),
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'TARGET_ADDED',
      resource: 'target',
      resourceId: target.id,
      engagementId: id,
      metadata: { type: target.type, value: target.value },
    });

    // DRAFT -> READY promotion when preconditions now hold.
    await c.orchestrator.markReadyIfEligible(engagement, request.user.id);

    reply.status(201);
    return toTargetResponse(target);
  });
}

function isDefaultPort(scheme: string, port: number): boolean {
  return (
    (scheme === 'http' && port === 80) ||
    (scheme === 'https' && port === 443) ||
    (scheme === 'ws' && port === 80) ||
    (scheme === 'wss' && port === 443)
  );
}
