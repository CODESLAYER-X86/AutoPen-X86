/** Shared helpers for the scripts/db/* lifecycle scripts. */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve } from 'node:path';
import { Client } from 'pg';

const require = createRequire(import.meta.url);

export const REPO_ROOT = resolve(import.meta.dirname, '..', '..');
export const PG_DATA_DIR = join(REPO_ROOT, 'data', 'pg');
export const PG_LOG_FILE = join(REPO_ROOT, 'data', 'pg.log');
export const PG_HOST = '127.0.0.1';
export const PG_PORT = 5433;
export const DATABASES = ['aegis', 'aegis_test'];

export function pgBin(name: 'initdb' | 'pg_ctl' | 'postgres'): string {
  const pkg = require.resolve('@embedded-postgres/linux-x64/package.json');
  return join(pkg, '..', 'native', 'bin', name);
}

export function adminConnectionString(): string {
  return `postgres://postgres@${PG_HOST}:${PG_PORT}/postgres`;
}

export async function isPostgresRunning(): Promise<boolean> {
  const client = new Client({ connectionString: adminConnectionString(), connectionTimeoutMillis: 1500 });
  try {
    await client.connect();
    await client.query('SELECT 1');
    await client.end();
    return true;
  } catch {
    try {
      await client.end();
    } catch {
      /* ignore */
    }
    return false;
  }
}

export function initCluster(): void {
  if (existsSync(join(PG_DATA_DIR, 'PG_VERSION'))) return;
  mkdirSync(join(REPO_ROOT, 'data'), { recursive: true });
  // Trust auth on localhost only: acceptable for a local development cluster
  // that listens on 127.0.0.1 (documented in docs/operations/development.md).
  execFileSync(pgBin('initdb'), ['-D', PG_DATA_DIR, '-U', 'postgres', '-A', 'trust', '-E', 'UTF8'], {
    stdio: 'inherit',
  });
}

export function startCluster(): void {
  execFileSync(
    pgBin('pg_ctl'),
    ['-D', PG_DATA_DIR, '-l', PG_LOG_FILE, '-o', `-p ${PG_PORT} -h ${PG_HOST}`, '-w', 'start'],
    { stdio: 'inherit' },
  );
}

export function stopCluster(): void {
  execFileSync(pgBin('pg_ctl'), ['-D', PG_DATA_DIR, '-m', 'fast', 'stop'], { stdio: 'inherit' });
}

export async function ensureDatabases(): Promise<void> {
  const client = new Client({ connectionString: adminConnectionString() });
  await client.connect();
  try {
    for (const db of DATABASES) {
      const result = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [db]);
      if (result.rowCount === 0) {
        await client.query(`CREATE DATABASE "${db}"`);
        console.log(`[db] created database ${db}`);
      }
    }
  } finally {
    await client.end();
  }
}

/** Start the cluster if it is not already running and ensure databases. */
export async function ensureRunning(): Promise<void> {
  if (!(await isPostgresRunning())) {
    initCluster();
    startCluster();
  }
  await ensureDatabases();
}
