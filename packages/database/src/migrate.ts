/**
 * SQL migration runner.
 *
 * - Migrations are plain .sql files under packages/database/migrations,
 *   applied in lexicographic order, each inside its own transaction.
 * - Applied migrations are recorded in `platform_migrations` together with
 *   the SHA-256 of the file. A later modification of an already-applied
 *   migration is detected and rejected (drift protection).
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Pool } from 'pg';
import { DatabaseError } from '@aegis/shared';

export interface MigrationReport {
  applied: string[];
  skipped: string[];
}

export async function runMigrations(pool: Pool, migrationsDir: string): Promise<MigrationReport> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_migrations (
      name text PRIMARY KEY,
      sha256 text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  if (files.length === 0) {
    throw new DatabaseError(`No migrations found in ${migrationsDir}`, 'NO_MIGRATIONS');
  }

  const existingRows = await pool.query<{ name: string; sha256: string }>(
    'SELECT name, sha256 FROM platform_migrations',
  );
  const existing = new Map(existingRows.rows.map((row) => [row.name, row.sha256]));

  const report: MigrationReport = { applied: [], skipped: [] };

  for (const file of files) {
    const sql = readFileSync(join(migrationsDir, file), 'utf8');
    const hash = createHash('sha256').update(sql, 'utf8').digest('hex');
    const previous = existing.get(file);
    if (previous !== undefined) {
      if (previous !== hash) {
        throw new DatabaseError(
          `Migration '${file}' was modified after being applied; refusing to run (hash drift)`,
          'MIGRATION_DRIFT',
          { file },
        );
      }
      report.skipped.push(file);
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO platform_migrations (name, sha256) VALUES ($1, $2)', [
        file,
        hash,
      ]);
      await client.query('COMMIT');
      report.applied.push(file);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      client.release();
      throw new DatabaseError(`Migration '${file}' failed`, 'MIGRATION_FAILED', undefined, error);
    }
    client.release();
  }

  return report;
}
