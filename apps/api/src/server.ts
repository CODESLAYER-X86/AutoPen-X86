/**
 * API server entry: config -> migrations -> listen -> graceful shutdown.
 * Run with `npm run dev:api` (tsx watch) or `node apps/api/dist/server.js`.
 */
import { join } from 'node:path';
import { runMigrations } from '@aegis/database';
import { loadConfig } from '@aegis/config';
import { createLogger } from '@aegis/logging';
import { ConfigurationError, isPlatformError } from '@aegis/shared';
import { buildApp } from './app.js';

const config = loadConfig({ envFile: join(import.meta.dirname, '..', '..', '..', '.env') });
const logger = createLogger({
  level: config.app.logLevel,
  bindings: { service: 'api', env: config.app.env },
});

const { createPool } = await import('@aegis/database');
const pool = createPool(config.database.url, { max: Math.min(config.database.poolMax, 2) });

try {
  const report = await runMigrations(pool, join(import.meta.dirname, '..', '..', '..', 'packages', 'database', 'migrations'));
  logger.info('db.migrations', {
    applied: report.applied.length,
    skipped: report.skipped.length,
  });
} catch (error) {
  if (isPlatformError(error)) {
    logger.error('db.migrations_failed', { code: error.code, message: error.message });
    throw new ConfigurationError(`Database migrations failed: ${error.message}`);
  }
  throw error;
}
await pool.end();

const app = await buildApp({ config, logger });

try {
  await app.listen({ port: config.app.port, host: '0.0.0.0' });
  logger.info('api.started', {
    port: config.app.port,
    app: config.app.name,
    mode_providers: {
      strategic: config.models.strategic.provider,
      tactical: config.models.tactical.provider,
    },
  });
} catch (error) {
  logger.error('api.start_failed', { message: error instanceof Error ? error.message : String(error) });
  process.exit(1);
}

const shutdown = async (signal: string): Promise<void> => {
  logger.info('api.shutdown', { signal });
  try {
    await app.close();
    process.exit(0);
  } catch {
    process.exit(1);
  }
};

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
