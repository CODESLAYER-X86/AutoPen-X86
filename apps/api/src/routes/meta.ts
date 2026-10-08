/** Public /api/meta route — non-sensitive runtime information. */
import type { FastifyInstance } from 'fastify';
import { PLATFORM_NAME, PLATFORM_VERSION } from '@aegis/shared';
import { MetaResponseSchema } from '@aegis/contracts';

export async function metaRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/meta', async () => {
    const c = app.ctx;
    const tools = c.toolRegistry.list();
    return MetaResponseSchema.parse({
      name: PLATFORM_NAME,
      version: PLATFORM_VERSION,
      environment: c.config.app.env,
      modes: ['PENTEST', 'CTF'],
      models: {
        strategic: {
          provider: c.config.models.strategic.provider,
          model_id: c.config.models.strategic.modelId,
        },
        tactical: {
          provider: c.config.models.tactical.provider,
          model_id: c.config.models.tactical.modelId,
        },
        google_api_key_configured: c.config.models.googleApiKeyConfigured,
      },
      features: {
        tools_http: c.config.features.toolsHttp,
        tools_browser: c.config.features.toolsBrowser,
        knowledge_search: c.config.features.knowledgeSearch,
        reporting: c.config.features.reporting,
      },
      capabilities: {
        tools_total: tools.length,
        tools_implemented: tools.filter((tool) => tool.implemented).length,
        // Explicit, honest signal: the autonomous loop is not in Part 1.
        autonomous_run_loop: false,
      },
    });
  });
}
