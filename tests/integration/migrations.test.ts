import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPool, runMigrations } from '@aegis/database';
import { DatabaseError } from '@aegis/shared';
import { TEST_DATABASE_URL } from './helpers.js';

const MIGRATIONS_DIR = join(__dirname, '..', '..', 'packages', 'database', 'migrations');
let pool: Awaited<ReturnType<typeof createPool>>;

beforeAll(async () => {
  pool = createPool(TEST_DATABASE_URL, { max: 2 });
});

afterAll(async () => {
  await pool.end();
});

describe('migration runner (spec §32, §38)', () => {
  it('is idempotent: a second run skips everything', async () => {
    const first = await runMigrations(pool, MIGRATIONS_DIR);
    expect(first.applied).toHaveLength(0);
    // Part 1 (12) + Part 2 (15) migrations.
    expect(first.skipped.length).toBe(27);
  });

  it('records hash-verified entries in platform_migrations', async () => {
    const result = await pool.query<{ name: string; sha256: string }>(
      'SELECT name, sha256 FROM platform_migrations ORDER BY name',
    );
    expect(result.rows.length).toBe(27);
    for (const row of result.rows) {
      expect(row.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(row.name).toMatch(/^\d{3}_.*\.sql$/);
    }
  });

  it('detects drift when an applied migration file changes', async () => {
    // Simulate drift: rewrite the recorded hash for one migration.
    const rows = await pool.query<{ name: string }>(
      'SELECT name FROM platform_migrations ORDER BY name LIMIT 1',
    );
    const target = rows.rows[0]!.name;
    await pool.query('UPDATE platform_migrations SET sha256 = $1 WHERE name = $2', [
      '0'.repeat(64),
      target,
    ]);
    // Restore the true hash so the suite stays consistent afterwards.
    const { readFileSync } = await import('node:fs');
    const { createHash } = await import('node:crypto');
    const sqlText = readFileSync(join(MIGRATIONS_DIR, target), 'utf8');
    const realHash = createHash('sha256').update(sqlText, 'utf8').digest('hex');

    try {
      await runMigrations(pool, MIGRATIONS_DIR);
      expect.unreachable('expected MIGRATION_DRIFT error');
    } catch (error) {
      expect(error).toBeInstanceOf(DatabaseError);
      expect((error as DatabaseError).code).toBe('MIGRATION_DRIFT');
    } finally {
      await pool.query('UPDATE platform_migrations SET sha256 = $1 WHERE name = $2', [
        realHash,
        target,
      ]);
    }
  });
});
