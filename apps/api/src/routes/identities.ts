/** Identity routes (spec §13). Session records are created by later parts;
 *  the API intentionally exposes identities only for now. */
import type { FastifyInstance } from 'fastify';
import { CreateIdentityRequestSchema, IdentitySchema } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { IdentityRecord } from '@aegis/database';
import { parseBody } from '../lib/validate.js';
import { requireOwnedEngagement } from '../lib/ownership.js';

export function toIdentityResponse(identity: IdentityRecord) {
  return IdentitySchema.parse({
    id: identity.id,
    engagement_id: identity.engagement_id,
    name: identity.name,
    role: identity.role,
    type: identity.type,
    metadata: identity.metadata,
    created_at: identity.created_at,
    updated_at: identity.updated_at,
  });
}

export async function identityRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/engagements/:id/identities', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);
    const identities = await c.repos.identities.listByEngagement(id);
    return { items: identities.map(toIdentityResponse), total: identities.length };
  });

  app.post('/api/engagements/:id/identities', async (request, reply) => {
    const body = parseBody(CreateIdentityRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedEngagement(c, request.user.id, id);

    const identity = await c.repos.identities.create({
      engagementId: id,
      name: body.name,
      role: body.role,
      type: body.type,
      metadata: body.metadata,
    });

    await c.eventBus.publish({
      type: 'IDENTITY_CREATED',
      engagement_id: id,
      trace_id: generateId('TRC'),
      actor_id: request.user.id,
      payload: { identity_id: identity.id, type: identity.type },
      occurred_at: new Date().toISOString(),
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'IDENTITY_CREATED',
      resource: 'identity',
      resourceId: identity.id,
      engagementId: id,
      metadata: { type: identity.type, role: identity.role },
    });

    reply.status(201);
    return toIdentityResponse(identity);
  });
}
