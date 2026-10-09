/**
 * Part 8 public operations routes (spec Part 8 §51-§52).
 *
 *   GET  /api/health   — liveness (never depends on dependencies)
 *   GET  /api/ready    — readiness (dependency probes, WAITING_FOR_RESOURCE)
 *
 * Health routes are PUBLIC (unauthenticated): orchestrators probe them
 * before any auth context exists. Metrics lives in the authenticated
 * security routes (routes/security.ts).
 */
import type { FastifyInstance } from 'fastify';

export async function opsRoutes(app: FastifyInstance): Promise<void> {
  // Liveness is process-local (§51: no dependency coupling).
  app.get('/api/health', async () => {
    return {
      status: 'ok',
      alive: true,
      uptime_seconds: Math.floor(process.uptime()),
      version: process.env.PLATFORM_VERSION ?? 'dev',
    };
  });

  // Readiness reflects dependency usability (§52).
  app.get('/api/ready', async () => {
    const ctx = app.ctx;
    if (!ctx.hardening) {
      return {
        ready: true,
        checked_at: new Date().toISOString(),
        waiting_for_resource: false,
        dependencies: [],
        note: 'hardening engine disabled; readiness limited to process liveness',
      };
    }
    const report = await ctx.hardening.health.readiness();
    return report;
  });
}
