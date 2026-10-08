/** Engagement routes: create, read, update. */
import type { FastifyInstance } from 'fastify';
import {
  CreateEngagementRequestSchema,
  EngagementDetailSchema,
  EngagementSchema,
  UpdateEngagementRequestSchema,
} from '@aegis/contracts';
import { NotFoundError, generateId } from '@aegis/shared';
import type { EngagementRecord } from '@aegis/database';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement, requireOwnedProject } from '../lib/ownership.js';

export function toEngagementResponse(engagement: EngagementRecord) {
  return EngagementSchema.parse({
    id: engagement.id,
    project_id: engagement.project_id,
    name: engagement.name,
    mode: engagement.mode,
    status: engagement.status,
    description: engagement.description,
    created_at: engagement.created_at,
    updated_at: engagement.updated_at,
    started_at: engagement.started_at,
    completed_at: engagement.completed_at,
  });
}

export async function engagementRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/engagements', async (request, reply) => {
    const body = parseBody(CreateEngagementRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');

    await requireOwnedProject(c, request.user.id, body.project_id);

    const engagement = await c.repos.engagements.create({
      projectId: body.project_id,
      name: body.name,
      mode: body.mode,
      description: body.description,
    });

    await c.eventBus.publish({
      type: 'ENGAGEMENT_CREATED',
      engagement_id: engagement.id,
      trace_id: generateId('TRC'),
      actor_id: request.user.id,
      payload: { name: engagement.name, mode: engagement.mode },
      occurred_at: new Date().toISOString(),
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'ENGAGEMENT_CREATED',
      resource: 'engagement',
      resourceId: engagement.id,
      engagementId: engagement.id,
      metadata: { mode: engagement.mode },
    });

    reply.status(201);
    return toEngagementResponse(engagement);
  });

  app.get('/api/engagements/:id', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);
    const readiness = await c.orchestrator.evaluateReadiness(engagement.id);
    return EngagementDetailSchema.parse({
      engagement: toEngagementResponse(engagement),
      readiness,
    });
  });

  app.get('/api/engagements', async (request) => {
    // Convenience listing scoped to the caller's projects.
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const projects = await c.repos.projects.listByOwner(request.user.id, 500, 0);
    const engagements: ReturnType<typeof toEngagementResponse>[] = [];
    for (const project of projects) {
      const records = await c.repos.engagements.listByProject(project.id);
      engagements.push(...records.map(toEngagementResponse));
    }
    return { items: engagements, total: engagements.length };
  });

  app.patch('/api/engagements/:id', async (request) => {
    const body = parseBody(UpdateEngagementRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);

    let updated: EngagementRecord;
    if (body.status !== undefined) {
      // Status changes route through the deterministic state machine.
      const result = await c.orchestrator.transition(engagement, body.status, {
        actorId: request.user.id,
      });
      updated = result.engagement;
    } else {
      const record = await c.repos.engagements.updateFields(id, {
        name: body.name,
        description: body.description,
      });
      if (!record) throw new NotFoundError('ENGAGEMENT');
      updated = record;
      await c.eventBus.publish({
        type: 'ENGAGEMENT_UPDATED',
        engagement_id: id,
        actor_id: request.user.id,
        payload: { fields: Object.keys(body) },
        occurred_at: new Date().toISOString(),
      });
    }

    await c.audit({
      actorUserId: request.user.id,
      action: 'ENGAGEMENT_UPDATED',
      resource: 'engagement',
      resourceId: id,
      engagementId: id,
      metadata: { fields: Object.keys(body) },
    });

    return toEngagementResponse(updated);
  });
}
