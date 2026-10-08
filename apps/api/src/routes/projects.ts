/** Project routes. */
import type { FastifyInstance } from 'fastify';
import { CreateProjectRequestSchema, ProjectSchema } from '@aegis/contracts';
import type { ProjectRecord } from '@aegis/database';
import { parseBody, parseQueryInt } from '../lib/validate.js';
import { requireOwnedProject } from '../lib/ownership.js';
import { toEngagementResponse } from './engagements.js';

export function toProjectResponse(project: ProjectRecord) {
  return ProjectSchema.parse({
    id: project.id,
    owner_id: project.owner_id,
    name: project.name,
    description: project.description,
    created_at: project.created_at,
    updated_at: project.updated_at,
  });
}

export async function projectRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/projects', async (request, reply) => {
    const body = parseBody(CreateProjectRequestSchema, request.body);
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');

    const project = await c.repos.projects.create({
      ownerId: request.user.id,
      name: body.name,
      description: body.description,
    });

    await c.audit({
      actorUserId: request.user.id,
      action: 'PROJECT_CREATED',
      resource: 'project',
      resourceId: project.id,
    });

    reply.status(201);
    return toProjectResponse(project);
  });

  app.get('/api/projects', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const limit = parseQueryInt((request.query as Record<string, string>).limit, 100, 1, 500);
    const offset = parseQueryInt((request.query as Record<string, string>).offset, 0, 0, 100_000);
    const [items, total] = await Promise.all([
      c.repos.projects.listByOwner(request.user.id, limit, offset),
      c.repos.projects.countByOwner(request.user.id),
    ]);
    return { items: items.map(toProjectResponse), total };
  });

  app.get('/api/projects/:id', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const project = await requireOwnedProject(c, request.user.id, id);
    return toProjectResponse(project);
  });

  app.get('/api/projects/:id/engagements', async (request) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireOwnedProject(c, request.user.id, id);
    const engagements = await c.repos.engagements.listByProject(id);
    return {
      items: engagements.map(toEngagementResponse),
      total: engagements.length,
    };
  });
}
