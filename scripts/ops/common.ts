/**
 * Shared helpers for scripts/ops (Part 8 §62-§63 backup + verified restore).
 *
 * The embedded PostgreSQL build ships no pg_dump, so backups are portable
 * Node logical dumps: schema object list + every table's rows in
 * deterministic (primary-key) order, serialized as SQL + JSON metadata.
 * Production deployments may substitute pg_dump (documented in
 * docs/operations/backup-restore.md) — the verification contract stays the
 * same: sha256 of the artifact + a restore into a scratch database.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { Client, type Pool } from 'pg';
import { loadConfig } from '@aegis/config';
import { runMigrations } from '@aegis/database';

const require = createRequire(import.meta.url);

export const REPO_ROOT = resolve(import.meta.dirname, '..', '..');

export function packageNativeRoot(): string {
  const candidates: string[] = [];
  try {
    const entry = require.resolve('@embedded-postgres/linux-x64');
    candidates.push(join(dirname(entry), '..'));
  } catch {
    /* fall through */
  }
  candidates.push(join(REPO_ROOT, 'node_modules', '@embedded-postgres', 'linux-x64'));
  const root = candidates.find((candidate) => existsSync(join(candidate, 'native', 'bin', 'postgres')));
  if (!root) throw new Error('[ops] @embedded-postgres native root not found');
  return root;
}

export function pgBin(name: string): string {
  return join(packageNativeRoot(), 'native', 'bin', name);
}

/** LD_LIBRARY_PATH including the vendored ICU/OpenSSL libraries. */
export function pgProcessEnv(): NodeJS.ProcessEnv {
  const vendoredLib = join(packageNativeRoot(), 'native', 'lib');
  const links: Array<[string, string]> = [
    ['libicudata.so.60.2', 'libicudata.so.60'],
    ['libicui18n.so.60.2', 'libicui18n.so.60'],
    ['libicuuc.so.60.2', 'libicuuc.so.60'],
  ];
  for (const [target, link] of links) {
    const linkPath = join(vendoredLib, link);
    if (!existsSync(linkPath) && existsSync(join(vendoredLib, target))) {
      require('node:fs').symlinkSync(target, linkPath);
    }
  }
  const existing = process.env.LD_LIBRARY_PATH ?? '';
  return { ...process.env, LD_LIBRARY_PATH: existing ? `${vendoredLib}:${existing}` : vendoredLib };
}

export function sha256File(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export interface LogicalDump {
  format: 'aegis-logical-sql';
  version: 1;
  created_at: string;
  database: string;
  tables: Array<{ table: string; row_count: number; sha256: string }>;
  statements: string[];
}

/** Deterministic logical dump of every public table (order: table name, pk). */
export async function logicalDump(pool: Pool, database: string): Promise<LogicalDump> {
  const tablesResult = await pool.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        AND table_name <> 'platform_migrations'
      ORDER BY table_name`,
  );
  const dump: LogicalDump = {
    format: 'aegis-logical-sql',
    version: 1,
    created_at: new Date().toISOString(),
    database,
    tables: [],
    statements: [],
  };
  for (const { table_name: table } of tablesResult.rows) {
    const pkResult = await pool.query<{ column_name: string }>(
      `SELECT a.attname AS column_name
         FROM pg_index i
         JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
        WHERE i.indrelid = $1::regclass AND i.indisprimary`,
      [`public.${table}`],
    );
    const orderBy = pkResult.rows.length > 0 ? `ORDER BY ${pkResult.rows.map((r) => `"${r.column_name}"`).join(', ')}` : '';
    const rows = await pool.query(`SELECT row_to_json(t) AS row FROM public."${table}" t ${orderBy}`);
    const serialized = rows.rows.map((r) => JSON.stringify(r.row)).join('\n');
    dump.tables.push({
      table,
      row_count: rows.rows.length,
      sha256: createHash('sha256').update(serialized, 'utf8').digest('hex'),
    });
    for (const row of rows.rows) {
      // Deterministic INSERTs keyed by jsonb row identity.
      const record = row.row as Record<string, unknown>;
      const columns = Object.keys(record).sort();
      dump.statements.push(
        `INSERT INTO public."${table}" (${columns.map((c) => `"${c}"`).join(', ')}) VALUES (${columns
          .map((c) => literal(record[c]))
          .join(', ')})`,
      );
    }
  }
  return dump;
}

/** SQL literal for a JSON-sourced value (dates arrive as ISO strings). */
function literal(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') return `'${JSON.stringify(value).replace(/'/g, "''")}'::jsonb`;
  return `'${String(value).replace(/'/g, "''")}'`;
}

export async function loadBackupEnv(): Promise<{ url: string; testUrl: string }> {
  const config = loadConfig({ envFile: join(REPO_ROOT, '.env') });
  return { url: config.database.url, testUrl: `${config.database.url.replace(/\/[^/]+$/, '')}/aegis_restore_check` };
}

export async function ensureScratchDatabase(adminUrl: string, scratchName: string): Promise<string> {
  const admin = new Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [scratchName]);
    if (exists.rowCount === 0) {
      await admin.query(`CREATE DATABASE "${scratchName}"`);
    }
  } finally {
    await admin.end();
  }
  return adminUrl.replace(/\/[^/]+$/, `/${scratchName}`);
}

export async function applyMigrations(pool: Pool): Promise<number> {
  const report = await runMigrations(pool, join(REPO_ROOT, 'packages', 'database', 'migrations'));
  return report.applied.length;
}

export { mkdirSync };
