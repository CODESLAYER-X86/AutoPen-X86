/**
 * Fastify application factory.
 *
 * Composition:
 *   request logging -> rate limit -> public routes (meta, auth)
 *   -> authenticated scope (bearer token) -> all domain routes
 *
 * `buildApp` is what tests drive with fastify.inject(); `server.ts` is the
 * process entry that adds migrations and listening.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import type { Pool } from 'pg';
import type { AppConfig } from '@aegis/config';
import type { Logger } from '@aegis/logging';
import { newRequestId } from '@aegis/shared';
import { createContext, type AppContext } from './context.js';
import { registerErrorHandler } from './plugins/error-handler.js';
import { registerSecurityHeaders } from './plugins/security-headers.js';
import { registerRateLimit } from './plugins/rate-limit.js';
import { registerAuthScope } from './plugins/auth.js';
import { publicAuthRoutes, protectedAuthRoutes } from './routes/auth.js';
import { metaRoutes } from './routes/meta.js';
import { toolsRoutes } from './routes/tools.js';
import { projectRoutes } from './routes/projects.js';
import { engagementRoutes } from './routes/engagements.js';
import { scopeRoutes } from './routes/scope.js';
import { targetRoutes } from './routes/targets.js';
import { identityRoutes } from './routes/identities.js';
import { lifecycleRoutes } from './routes/lifecycle.js';
import { telemetryRoutes } from './routes/telemetry.js';
import { agentRoutes } from './routes/agent.js';
import { httpRoutes } from './routes/http.js';
import { browserRoutes } from './routes/browser.js';
import { reasoningRoutes } from './routes/reasoning.js';
import { knowledgeRoutes } from './routes/knowledge.js';

export interface BuildAppOptions {
  config?: AppConfig;
  logger?: Logger;
  pool?: Pool;
}

export async function buildApp(options: BuildAppOptions = {}): Promise<FastifyInstance> {
  const ctx: AppContext = createContext(options);
  const logger = ctx.logger;

  const app = Fastify({
    genReqId: () => newRequestId(),
    bodyLimit: ctx.config.http.maxBodyBytes,
    logger: false,
    disableRequestLogging: true,
  });

  app.decorate('ctx', ctx);
  app.decorateRequest('user', undefined);

  // --- Request/response observability (path only, no query strings) ---
  app.addHook('onRequest', async (request) => {
    (request as unknown as { startedAt?: number }).startedAt = Date.now();
  });
  app.addHook('onResponse', async (request, reply) => {
    const startedAt = (request as unknown as { startedAt?: number }).startedAt;
    logger.info('http.request', {
      request_id: request.id,
      method: request.method,
      path: request.raw.url?.split('?')[0],
      status: reply.statusCode,
      duration_ms: startedAt === undefined ? undefined : Date.now() - startedAt,
      user_id: request.user?.id,
    });
  });

  registerErrorHandler(app);
  registerSecurityHeaders(app);
  registerRateLimit(app, ctx.config);

  await app.register(cors, {
    origin: ctx.config.security.corsOrigins,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  });

  // --- Public scope: meta + register/login ---
  await app.register(metaRoutes);
  await app.register(publicAuthRoutes);

  // --- Authenticated scope: everything else ---
  await app.register(async (authenticated) => {
    registerAuthScope(authenticated);
    await authenticated.register(protectedAuthRoutes);
    await authenticated.register(toolsRoutes);
    await authenticated.register(projectRoutes);
    await authenticated.register(engagementRoutes);
    await authenticated.register(scopeRoutes);
    await authenticated.register(targetRoutes);
    await authenticated.register(identityRoutes);
    await authenticated.register(lifecycleRoutes);
    await authenticated.register(telemetryRoutes);
    await authenticated.register(agentRoutes);
    await authenticated.register(httpRoutes);
    await authenticated.register(browserRoutes);
    await authenticated.register(reasoningRoutes);
    await authenticated.register(knowledgeRoutes);
  });

  // Part 3 §75: browser cleanup even on graceful shutdown paths.
  app.addHook('onClose', async () => {
    // Part 4 §109: stop the reasoning event subscription first so no new
    // derived writes race the shutdown.
    ctx.stopReasoning?.();
    const engagements = await ctx.pool
      .query<{ id: string }>('SELECT DISTINCT engagement_id AS id FROM browser_contexts')
      .then((result) => result.rows.map((row) => row.id))
      .catch(() => [] as string[]);
    for (const engagementId of engagements) {
      await ctx.browserService.closeEngagement(engagementId).catch(() => undefined);
    }
  });

  return app;
}
