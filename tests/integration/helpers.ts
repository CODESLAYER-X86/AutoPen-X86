/** Integration/security test helpers: isolated app instances + DB reset. */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { Client, type Pool } from 'pg';
import { loadConfig, type AppConfig } from '@aegis/config';
import { createPool } from '@aegis/database';
import { createLogger, createMemorySink, type Logger } from '@aegis/logging';
import { buildApp } from '../../apps/api/src/app.js';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

export interface TestApp {
  app: FastifyInstance;
  pool: Pool;
  logger: Logger;
  sink: { sink: { write(line: string): void }; lines: string[] };
  config: AppConfig;
  close: () => Promise<void>;
}

export interface TestAppOptions {
  overrides?: Record<string, string | undefined>;
  /** Override config object wholesale (rare). */
  config?: AppConfig;
}

export function buildTestConfig(overrides: Record<string, string | undefined> = {}): AppConfig {
  const temp = mkdtempSync(join(tmpdir(), 'aegis-test-'));
  return loadConfig({
    env: {
      NODE_ENV: 'test',
      APP_LOG_LEVEL: 'info',
      DATABASE_URL: TEST_DATABASE_URL,
      // Keep limits high so functional tests never trip the limiter.
      RATE_LIMIT_MAX_REQUESTS: '10000',
      AUTH_RATE_LIMIT_MAX: '10000',
      SECRET_STORE_PATH: join(temp, 'secrets.json'),
      STORAGE_LOCAL_PATH: join(temp, 'artifacts'),
      ...overrides,
    },
  });
}

export async function createTestApp(options: TestAppOptions = {}): Promise<TestApp> {
  const config = options.config ?? buildTestConfig(options.overrides);
  const memory = createMemorySink();
  const logger = createLogger({ level: config.app.logLevel, sink: memory.sink });
  const pool = createPool(config.database.url, { max: 5 });
  const app = await buildApp({ config, logger, pool });

  return {
    app,
    pool,
    logger,
    sink: memory,
    config,
    close: async () => {
      await app.close();
      await pool.end();
    },
  };
}

/** Truncate all domain tables (migrations table preserved). */
export async function resetDatabase(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    const result = await client.query<{ tablename: string }>(
      `SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'platform_migrations'`,
    );
    const tables = result.rows.map((row) => `"${row.tablename}"`).join(', ');
    if (tables.length > 0) {
      await client.query(`TRUNCATE TABLE ${tables} RESTART IDENTITY CASCADE`);
    }
  } finally {
    client.release();
  }
}

/** Registers a fresh user and returns the bearer token. */
export async function registerAndLogin(
  app: FastifyInstance,
  email: string,
  password = 'password1234',
): Promise<{ token: string; userId: string }> {
  const register = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    payload: { email, name: `Test ${email}`, password },
  });
  if (register.statusCode !== 201) {
    throw new Error(`register failed: ${register.statusCode} ${register.body}`);
  }
  const login = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email, password },
  });
  if (login.statusCode !== 200) {
    throw new Error(`login failed: ${login.statusCode} ${login.body}`);
  }
  const body = JSON.parse(login.body) as { token: string; user: { id: string } };
  return { token: body.token, userId: body.user.id };
}

export function authHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Direct SQL access for assertions that bypass the API. */
export async function sql<T extends Record<string, unknown>>(
  pool: Pool,
  query: string,
  params: unknown[] = [],
): Promise<T[]> {
  const result = await pool.query<T>(query, params);
  return result.rows;
}

export { Client };
