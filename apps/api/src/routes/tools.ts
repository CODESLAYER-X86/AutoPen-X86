/** Tool registry listing (authenticated) — surfaces implemented vs planned. */
import type { FastifyInstance } from 'fastify';

export async function toolsRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/tools', async () => {
    const tools = app.ctx.toolRegistry.list();
    return {
      items: tools,
      total: tools.length,
      implemented: tools.filter((tool) => tool.implemented).length,
    };
  });
}
