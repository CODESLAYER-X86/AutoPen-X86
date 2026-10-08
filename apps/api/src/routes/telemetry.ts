/** Telemetry routes: events (activity), audit, evidence. */
import type { FastifyInstance } from 'fastify';
import { EngagementEventSchema, EvidenceSchema } from '@aegis/contracts';
import type { AuditRecord, EvidenceRecord, EventRecord } from '@aegis/database';
import { parseQueryInt } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

function toEventResponse(event: EventRecord) {
  return EngagementEventSchema.parse({
    id: event.id,
    type: event.type,
    engagement_id: event.engagement_id,
    task_id: event.task_id,
    trace_id: event.trace_id,
    actor_id: event.actor_id,
    payload: event.payload,
    occurred_at: event.occurred_at,
  });
}

function toAuditResponse(entry: AuditRecord) {
  return {
    id: entry.id,
    actor_user_id: entry.actor_user_id,
    action: entry.action,
    resource: entry.resource,
    resource_id: entry.resource_id,
    engagement_id: entry.engagement_id,
    metadata: entry.metadata,
    created_at: entry.created_at,
  };
}

export function toEvidenceResponse(record: EvidenceRecord) {
  return EvidenceSchema.parse({
    id: record.id,
    engagement_id: record.engagement_id,
    type: record.type,
    source: record.source,
    content_reference: record.content_reference,
    sha256: record.sha256,
    parent_id: record.parent_id,
    task_id: record.task_id,
    metadata: record.metadata,
    created_at: record.created_at,
  });
}

export async function telemetryRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/engagements/:id/events', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as Record<string, string>).limit, 100, 1, 500);
    const events = await c.repos.events.listByEngagement(id, limit);
    return { items: events.map(toEventResponse), total: events.length };
  });

  app.get('/api/engagements/:id/audit', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const limit = parseQueryInt((request.query as Record<string, string>).limit, 100, 1, 500);
    const entries = await c.repos.audit.listByEngagement(id, limit);
    return { items: entries.map(toAuditResponse), total: entries.length };
  });

  app.get('/api/engagements/:id/evidence', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const records = await c.evidence.list(id);
    return { items: records.map(toEvidenceResponse), total: records.length };
  });

  app.get('/api/engagements/:id/evidence/:evidenceId/verify', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id, evidenceId } = request.params as { id: string; evidenceId: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const result = await c.evidence.verify(evidenceId);
    await c.audit({
      actorUserId: request.user.id,
      action: 'EVIDENCE_VERIFIED',
      resource: 'evidence',
      resourceId: evidenceId,
      engagementId: id,
      metadata: { verified: result.verified },
    });
    return result;
  });
}
