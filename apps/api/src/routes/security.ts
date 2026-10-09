/**
 * Part 8 security routes (spec Part 8 §11, §15, §59, §85-§93).
 *
 *   GET    /api/security/events            — incident timeline events
 *   GET    /api/security/incidents         — open incidents
 *   POST   /api/security/incidents/:id     — update incident status
 *   GET    /api/security/breakers          — open circuit breakers
 *   POST   /api/security/breakers/:id/reset — human reset (§98)
 *   GET    /api/security/emergency-stop    — stop state
 *   POST   /api/security/emergency-stop/engage   — global stop (§89)
 *   POST   /api/security/emergency-stop/release  — release (human only)
 *   GET    /api/api-keys                   — list own API credentials
 *   POST   /api/api-keys                   — create (token shown once)
 *   POST   /api/api-keys/:id/revoke        — revoke
 *   GET    /api/engagements/:id/grants     — scoped credential grants
 *   POST   /api/engagements/:id/grants     — issue grant (§14)
 *   POST   /api/engagements/:id/grants/:gid/revoke — kill switch (§93)
 *   GET    /api/engagements/:id/scope-versions      — version history (§92)
 *   POST   /api/engagements/:id/scope-versions      — propose (§91)
 *   POST   /api/engagements/:id/scope-versions/:vid/activate — confirm
 *   GET    /api/audit-chain                — tail of the hash-chained log
 *   POST   /api/audit-chain/verify         — tamper-evidence check (§85)
 *   GET    /api/retention                  — retention policies (§59)
 *   POST   /api/retention/sweep            — apply retention (§60)
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { NotFoundError, NotImplementedError, ValidationError } from '@aegis/shared';
import {
  ApiCredentialKindSchema,
  CreateApiCredentialRequestSchema,
  CreateCredentialGrantRequestSchema,
  IncidentRecordSchema,
  RaiseSecurityEventRequestSchema,
  SecurityEventRecordSchema,
} from '@aegis/contracts';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

export async function securityRoutes(app: FastifyInstance): Promise<void> {
  const engine = () => {
    const ctx = app.ctx;
    if (!ctx.hardening) {
      throw new NotImplementedError(
        'The hardening engine (Part 8) is disabled in this deployment; set FEATURE_HARDENING=true to enable it',
        'HARDENING_ENGINE_DISABLED',
      );
    }
    return ctx.hardening;
  };

  const parseId = (value: string | undefined): string => {
    if (!value || value.length === 0 || value.length > 64) {
      throw new ValidationError('Invalid identifier', 'INVALID_ID');
    }
    return value;
  };

  // ------------------------------------------------------------- metrics (§49)

  app.get('/api/metrics', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const snapshot = await engine().securityEvents.securityMetricsSnapshot();
    const pendingOutbox = await engine().outbox.countPending();
    return { ...snapshot, pending_outbox_events: pendingOutbox, checked_at: new Date().toISOString() };
  });

  // ------------------------------------------------------------ events (§94-96)


  app.get('/api/security/events', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const query = request.query as { severity?: string; engagement_id?: string; limit?: string };
    const events = await engine().securityEvents.list({
      severity: query.severity,
      engagementId: query.engagement_id,
      limit: query.limit ? Number(query.limit) : 100,
    });
    return { items: events.map((event) => SecurityEventRecordSchema.parse(event)) };
  });

  app.get('/api/security/incidents', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const incidents = await engine().securityEvents.listOpenIncidents();
    return { items: incidents.map((incident) => IncidentRecordSchema.parse(incident)) };
  });

  app.post('/api/security/incidents/:id', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      z.object({ status: z.enum(['OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED']) }).strict(),
      request.body,
    );
    const { id } = request.params as { id: string };
    const updated = await engine().securityEvents.updateIncidentStatus(parseId(id), body.status);
    if (!updated) throw new NotFoundError('Incident not found', 'INCIDENT_NOT_FOUND');
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'incident.status_changed',
      resource: 'incident',
      resourceId: id,
      metadata: { status: body.status },
    });
    return IncidentRecordSchema.parse(updated);
  });

  app.post('/api/security/events', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    // Operators may raise events manually; severity floors still apply.
    const body = parseBody(RaiseSecurityEventRequestSchema, request.body);
    const event = await engine().securityEvents.raise({ ...body, actor: 'USER' });
    return SecurityEventRecordSchema.parse(event);
  });

  // ------------------------------------------------------------ breakers (§98-99)

  app.get('/api/security/breakers', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const breakers = await engine().circuitBreakers.listOpen();
    return { items: breakers };
  });

  app.post('/api/security/breakers/:id/reset', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const reset = await engine().circuitBreakers.reset(parseId(id));
    if (!reset) throw new NotFoundError('Circuit breaker not found or not OPEN', 'BREAKER_NOT_FOUND');
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'circuit_breaker.reset',
      resource: 'circuit_breaker',
      resourceId: id,
      metadata: {},
    });
    return reset;
  });

  // ------------------------------------------------------- emergency stop (§89-90)

  app.get('/api/security/emergency-stop', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    return engine().emergencyStop.getState();
  });

  app.post('/api/security/emergency-stop/engage', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      z.object({ reason: z.string().min(1).max(500) }).strict(),
      request.body,
    );
    const state = await engine().emergencyStop.engage({
      engagedBy: request.user.id,
      reason: body.reason,
    });
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'emergency_stop.engaged',
      resource: 'platform',
      metadata: { reason: body.reason, cancelled_tasks: state.cancelled_tasks, revoked_grants: state.revoked_grants },
    });
    return state;
  });

  app.post('/api/security/emergency-stop/release', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const state = await engine().emergencyStop.release();
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'emergency_stop.released',
      resource: 'platform',
      metadata: {},
    });
    return state;
  });

  // ------------------------------------------------------------ API keys (§11)

  app.get('/api/api-keys', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const items = await engine().credentials.listApiCredentials(request.user.id);
    return { items: items.map(({ token_hash: _hash, ...rest }) => rest) };
  });

  app.post('/api/api-keys', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      CreateApiCredentialRequestSchema.extend({ kind: ApiCredentialKindSchema }),
      request.body,
    );
    const created = await engine().credentials.createApiCredential({
      userId: request.user.id,
      kind: body.kind,
      name: body.name,
      scopes: body.scopes,
      ttlHours: body.ttl_hours,
    });
    // The plaintext token is returned exactly once (§11: never stored raw).
    const { token_hash: _hash, ...record } = created.record;
    return { ...record, token: created.token };
  });

  app.post('/api/api-keys/:id/revoke', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const revoked = await engine().credentials.revokeApiCredential({
      id: parseId(id),
      userId: request.user.id,
    });
    if (!revoked) throw new NotFoundError('API credential not found', 'API_CREDENTIAL_NOT_FOUND');
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'api_credential.revoked',
      resource: 'api_credential',
      resourceId: id,
      metadata: {},
    });
    return { revoked: true };
  });

  // -------------------------------------------------- credential grants (§14-15, §93)

  app.get('/api/engagements/:id/grants', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(app.ctx, request.user.id, id);
    const items = await engine().credentials.listGrants(id);
    return { items: items.map(({ secret_reference: ref, ...rest }) => ({ ...rest, secret_reference: `${ref.slice(0, 8)}…` })) };
  });

  app.post('/api/engagements/:id/grants', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(app.ctx, request.user.id, id);
    if (engagement.status !== 'RUNNING' && engagement.status !== 'PAUSED') {
      throw new ValidationError(
        `Credential grants require the engagement to be RUNNING or PAUSED (current: ${engagement.status})`,
        'GRANT_REQUIRES_ACTIVE_ENGAGEMENT',
      );
    }
    const body = parseBody(CreateCredentialGrantRequestSchema, request.body);
    const grant = await engine().credentials.issueGrant({
      engagementId: id,
      identityId: body.identity_id,
      targetId: body.target_id,
      secretReference: body.secret_reference,
      purpose: body.purpose,
      ttlMinutes: body.ttl_minutes,
      actorUserId: request.user.id,
    });
    const { secret_reference: _ref, ...rest } = grant;
    return rest;
  });

  app.post('/api/engagements/:id/grants/:gid/revoke', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id, gid } = request.params as { id: string; gid: string };
    await requireOwnedEngagement(app.ctx, request.user.id, id);
    const body = parseBody(
      z.object({ reason: z.string().min(1).max(500) }).strict(),
      request.body,
    );
    const revoked = await engine().credentials.revokeGrant({
      id: parseId(gid),
      engagementId: id,
      actorUserId: request.user.id,
      reason: body.reason,
    });
    if (!revoked) throw new NotFoundError('Credential grant not found or already terminal', 'GRANT_NOT_FOUND');
    return { revoked: true };
  });

  // ------------------------------------------------------- scope versions (§91-92)

  app.get('/api/engagements/:id/scope-versions', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(app.ctx, request.user.id, id);
    return { items: await engine().scopeVersions.listByEngagement(id) };
  });

  app.post('/api/engagements/:id/scope-versions', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(app.ctx, request.user.id, id);
    const body = parseBody(
      z
        .object({
          allowed_hosts: z.array(z.string().min(1).max(253)).max(100),
          allowed_domains: z.array(z.string().min(1).max(253)).max(100),
          allowed_ports: z.array(z.number().int().min(1).max(65535)).max(64),
          allowed_schemes: z.array(z.enum(['http', 'https', 'ws', 'wss'])).max(4),
          excluded_hosts: z.array(z.string().min(1).max(253)).max(100),
          rate_limit: z.number().int().min(1).max(1000).nullable().optional(),
          concurrency_limit: z.number().int().min(1).max(64).nullable().optional(),
          destructive_actions_allowed: z.boolean(),
        })
        .strict(),
      request.body,
    );
    const record = await engine().scopeVersions.propose({
      engagementId: id,
      scope: body,
      createdBy: request.user.id,
    });
    return record;
  });

  app.post('/api/engagements/:id/scope-versions/:vid/activate', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id, vid } = request.params as { id: string; vid: string };
    await requireOwnedEngagement(app.ctx, request.user.id, id);
    const record = await engine().scopeVersions.activate({
      id: parseId(vid),
      engagementId: id,
      actorUserId: request.user.id,
    });
    return record;
  });

  // ----------------------------------------------------------- audit chain (§85)

  app.get('/api/audit-chain', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const query = request.query as { limit?: string };
    return { items: await engine().audit.listChain(query.limit ? Number(query.limit) : 50) };
  });

  app.post('/api/audit-chain/verify', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const verification = await engine().verifyAuditChain();
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'audit_chain.verified',
      resource: 'audit_log',
      metadata: { verified: verification.verified, records: verification.recordsChecked },
    });
    return {
      verified: verification.verified,
      records_checked: verification.recordsChecked,
      first_broken_record_id: verification.firstBrokenRecordId,
      reason: verification.reason,
    };
  });

  // ------------------------------------------------------------- retention (§59-60)

  app.get('/api/retention', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    return { items: await engine().retention.listPolicies() };
  });

  app.post('/api/retention', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(
      z
        .object({
          data_class: z.enum([
            'RAW_HTTP', 'SCREENSHOTS', 'BROWSER_TRACES', 'HAR', 'SOURCE_ARTIFACTS',
            'REPORTS', 'AGENT_TRACES', 'LOGS', 'EVALUATION_DATA',
          ]),
          retention_days: z.number().int().min(0).max(36500),
          hard_delete: z.boolean(),
        })
        .strict(),
      request.body,
    );
    const updated = await engine().retention.updatePolicy({
      dataClass: body.data_class,
      retentionDays: body.retention_days,
      hardDelete: body.hard_delete,
    });
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'retention_policy.updated',
      resource: 'retention_policy',
      resourceId: updated.id,
      metadata: { data_class: body.data_class, retention_days: body.retention_days },
    });
    return updated;
  });

  app.post('/api/retention/sweep', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const results = await engine().retention.applyRetention({ batchSize: 100 });
    await app.ctx.audit({
      actorUserId: request.user.id,
      action: 'retention.sweep_applied',
      resource: 'platform',
      metadata: { results },
    });
    return { results };
  });
}
