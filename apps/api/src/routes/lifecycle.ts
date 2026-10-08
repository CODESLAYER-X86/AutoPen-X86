/** Engagement lifecycle routes (spec §27, §31). */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { requireOwnedEngagement } from '../lib/ownership.js';
import { toEngagementResponse } from './engagements.js';

export async function lifecycleRoutes(app: FastifyInstance): Promise<void> {
  const transition = async (
    request: FastifyRequest,
    action: 'start' | 'pause' | 'resume' | 'cancel',
  ) => {
    const c = app.ctx;
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const engagement = await requireOwnedEngagement(c, request.user.id, id);

    const result =
      action === 'start'
        ? await c.orchestrator.start(engagement, request.user.id)
        : action === 'pause'
          ? await c.orchestrator.pause(engagement, request.user.id)
          : action === 'resume'
            ? await c.orchestrator.resume(engagement, request.user.id)
            : await c.orchestrator.cancel(engagement, request.user.id);

    return toEngagementResponse(result.engagement);
  };

  app.post('/api/engagements/:id/start', async (request) => transition(request, 'start'));
  app.post('/api/engagements/:id/pause', async (request) => transition(request, 'pause'));
  app.post('/api/engagements/:id/resume', async (request) => transition(request, 'resume'));
  app.post('/api/engagements/:id/cancel', async (request) => transition(request, 'cancel'));
}
