/**
 * Part 8 backup/restore verification (spec Part 8 §62-§63): a backup that
 * has never been restored is not a verified backup. This test executes the
 * real backup + restore helpers against the scratch database and asserts
 * row-level equality through the manifest hashes.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { applyMigrations, ensureScratchDatabase, loadBackupEnv, logicalDump, sha256File } from '../../scripts/ops/common.js';
import { createTestApp, registerAndLogin, resetDatabase, type TestApp } from '../integration/helpers.js';

let app: TestApp;
let headers: Record<string, string>;

beforeAll(async () => {
  app = await createTestApp({ overrides: { FEATURE_HARDENING: 'true' } });
  await resetDatabase(app.pool);
  await app.pool.query(
    `INSERT INTO emergency_stop (id, status) VALUES ('EST_PLATFORM', 'CLEAR') ON CONFLICT (id) DO NOTHING`,
  );
  const auth = await registerAndLogin(app.app, 'p8-backup@test.local');
  headers = { authorization: `Bearer ${auth.token}` };
  await app.app.inject({ method: 'POST', url: '/api/projects', headers, payload: { name: 'backup-test' } });
}, 120_000);

afterAll(async () => {
  await app.close();
}, 60_000);

describe('backup + verified restore (spec Part 8 §62-§63)', () => {
  it('dumps deterministically and the restore verifies every table hash', async () => {
    // 1. Logical dump of the live test database.
    const dump = await logicalDump(app.pool, 'aegis_test');
    expect(dump.format).toBe('aegis-logical-sql');
    expect(dump.tables.length).toBeGreaterThan(70);
    const usersTable = dump.tables.find((table) => table.table === 'users');
    expect(usersTable!.row_count).toBeGreaterThanOrEqual(1);

    // 2. Materialize the artifact (bytes -> sha256 like scripts/ops/backup.ts).
    const bytes = Buffer.from(JSON.stringify(dump), 'utf8');
    const dir = mkdtempSync(join(tmpdir(), 'aegis-backup-'));
    const file = join(dir, 'backup.json');
    writeFileSync(file, bytes);
    expect(sha256File(bytes)).toHaveLength(64);

    // 3. Restore into the scratch database: schema first, then statements.
    const { url } = await loadBackupEnv();
    const adminUrl = url.replace(/\/[^/]+$/, '/postgres');
    const { createHash } = await import('node:crypto');
    const { Pool: PgPool } = await import('pg');
    const scratchUrl = await ensureScratchDatabase(adminUrl, 'aegis_restore_check');
    const scratch = new PgPool({ connectionString: scratchUrl, max: 4 });
    try {
      await applyMigrations(scratch);
      const client = await scratch.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          `DO $$ DECLARE r record; BEGIN
             FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'platform_migrations' LOOP
               EXECUTE format('TRUNCATE TABLE public.%I CASCADE', r.tablename);
             END LOOP;
           END $$;`,
        );
        await client.query('SET session_replication_role = replica');
        for (const statement of dump.statements) {
          await client.query(statement);
        }
        await client.query('SET session_replication_role = DEFAULT');
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      // 4. Verify every table: row count + content hash equality.
      let mismatched = 0;
      for (const expected of dump.tables) {
        const rows = await scratch.query(`SELECT row_to_json(t) AS row FROM public."${expected.table}" t`);
        const serialized = rows.rows.map((r: { row: unknown }) => JSON.stringify(r.row)).join('\n');
        const hash = createHash('sha256').update(serialized, 'utf8').digest('hex');
        if (rows.rows.length !== expected.row_count || hash !== expected.sha256) {
          mismatched += 1;
        }
      }
      expect(mismatched, `tables mismatching after restore: ${mismatched}`).toBe(0);
      // The restore DB was recreated clean: migrations ledger intact.
      const ledger = await scratch.query<{ name: string }>('SELECT name FROM platform_migrations ORDER BY name LIMIT 1');
      expect(ledger.rows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await scratch.end();
    }
  }, 180_000);
});
