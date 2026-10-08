/**
 * Integration test global setup: ensures the test database exists and all
 * migrations are applied. Requires PostgreSQL (npm run db:ensure).
 */
import { resolve } from 'node:path';
import { Client } from 'pg';

const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5433/aegis_test';

export default async function globalSetup(): Promise<void> {
  const url = new URL(TEST_DATABASE_URL);
  const dbName = url.pathname.replace(/^\//, '');
  // Rebuild the admin URL preserving credentials (postgres db).
  const adminUrl = new URL(TEST_DATABASE_URL);
  adminUrl.pathname = '/postgres';

  const admin = new Client({ connectionString: adminUrl.toString(), connectionTimeoutMillis: 5000 });
  try {
    await admin.connect();
  } catch (cause) {
    throw new Error(
      `Cannot reach PostgreSQL at ${url.host}. Run \`npm run db:ensure\` first. (${(cause as Error).message})`,
    );
  }

  const exists = await admin.query<{ ok: number }>('SELECT 1 AS ok FROM pg_database WHERE datname = $1', [
    dbName,
  ]);
  if (exists.rowCount === 0) {
    await admin.query(`CREATE DATABASE "${dbName}"`);
  }
  await admin.end();

  const { createPool, runMigrations } = await import('@aegis/database');
  const pool = createPool(TEST_DATABASE_URL, { max: 2 });
  const report = await runMigrations(
    pool,
    resolve(__dirname, '..', '..', 'packages', 'database', 'migrations'),
  );
  await pool.end();
  console.log(`[global-setup] migrations: ${report.applied.length} applied, ${report.skipped.length} skipped`);
}
