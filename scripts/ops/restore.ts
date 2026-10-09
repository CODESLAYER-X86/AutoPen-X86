/**
 * Part 8 §62-§63: verified restore — loads a backup artifact into a scratch
 * database and verifies every table's row count + content hash, then marks
 * the backup restore_verified. An untested backup is not a verified backup.
 *
 *   npx tsx scripts/ops/restore.ts <backup-file.json>
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Client, type Pool } from 'pg';
import { createPool } from '@aegis/database';
import { applyMigrations, ensureScratchDatabase, loadBackupEnv } from './common.js';

const file = process.argv[2];
if (!file) {
  console.error('usage: npx tsx scripts/ops/restore.ts <backup-file.json>');
  process.exit(1);
}

const artifact = JSON.parse(readFileSync(file, 'utf8')) as {
  format: string;
  tables: Array<{ table: string; row_count: number; sha256: string }>;
  statements: string[];
};
if (artifact.format !== 'aegis-logical-sql') {
  throw new Error(`Unknown backup format: ${artifact.format}`);
}

const { url } = await loadBackupEnv();
const adminUrl = url.replace(/\/[^/]+$/, '/postgres');
const scratchUrl = await ensureScratchDatabase(adminUrl, 'aegis_restore_check');

// Recreate from scratch: drop + create so restore is repeatable.
const admin = new Client({ connectionString: adminUrl });
await admin.connect();
try {
  await admin.query('DROP DATABASE IF EXISTS aegis_restore_check');
  await admin.query('CREATE DATABASE aegis_restore_check');
} finally {
  await admin.end();
}

const scratch: Pool = createPool(scratchUrl, { max: 4 });
try {
  // 1. Schema first (versioned migrations), then data.
  await applyMigrations(scratch);

  const client = await scratch.connect();
  try {
    await client.query('BEGIN');
    // Clear existing rows first: migrations seed singleton rows (emergency
    // stop, retention defaults) that the dump also contains.
    await client.query(
      `DO $$ DECLARE r record; BEGIN
         FOR r IN SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'platform_migrations' LOOP
           EXECUTE format('TRUNCATE TABLE public.%I CASCADE', r.tablename);
         END LOOP;
       END $$;`,
    );
    // Defensive ordering: statements were emitted in table-name order which
    // matches FK dependencies in this schema; disable triggers for restore.
    await client.query('SET session_replication_role = replica');
    for (const statement of artifact.statements) {
      await client.query(statement);
    }
    await client.query('SET session_replication_role = DEFAULT');
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }

  // 2. Verify every table's row count + content hash against the manifest.
  let mismatches = 0;
  for (const expected of artifact.tables) {
    const rows = await scratch.query(`SELECT row_to_json(t) AS row FROM public."${expected.table}" t`);
    const serialized = rows.rows.map((r) => JSON.stringify(r.row)).join('\n');
    const hash = createHash('sha256').update(serialized, 'utf8').digest('hex');
    const countOk = rows.rows.length === expected.row_count;
    const hashOk = hash === expected.sha256;
    if (!countOk || !hashOk) {
      mismatches += 1;
      console.error(
        `[restore] MISMATCH ${expected.table}: rows ${rows.rows.length}/${expected.row_count}, hash ${hash.slice(0, 12)}…/${expected.sha256.slice(0, 12)}…`,
      );
    }
  }
  if (mismatches > 0) {
    throw new Error(`[restore] verification failed for ${mismatches} table(s)`);
  }
  console.log(
    `[restore] verified ${artifact.tables.length} tables (${artifact.tables.reduce((acc, t) => acc + t.row_count, 0)} rows) in aegis_restore_check`,
  );
} finally {
  await scratch.end();
}

// 3. Mark the source backup as restore-verified (audit trail).
const source = createPool(url, { max: 2 });
try {
  const sha = createHash('sha256').update(readFileSync(file).toString('utf8'), 'utf8').digest('hex');
  const marked = await source.query(
    'UPDATE backup_records SET restore_verified_at = now() WHERE sha256 = $1 AND restore_verified_at IS NULL',
    [sha],
  );
  console.log(`[restore] marked ${marked.rowCount ?? 0} backup record(s) as restore-verified`);
} finally {
  await source.end();
}
