/**
 * Part 8 §62: backup script — deterministic logical dump, sha256 artifact,
 * backup_records row. Usage:
 *
 *   npx tsx scripts/ops/backup.ts [label]
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPool } from '@aegis/database';
import { applyMigrations, loadBackupEnv, logicalDump, REPO_ROOT, sha256File } from './common.js';

const label = process.argv[2] ?? `manual-${new Date().toISOString().slice(0, 19)}`;
const { url } = await loadBackupEnv();
const pool = createPool(url, { max: 4 });
try {
  const dump = await logicalDump(pool, 'aegis');
  const body = JSON.stringify(dump, null, 2);
  const bytes = Buffer.from(body, 'utf8');
  const dir = join(REPO_ROOT, 'data', 'backups');
  const { mkdirSync } = await import('node:fs');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${new Date().toISOString().replace(/[:.]/g, '-')}-${label.replace(/[^a-zA-Z0-9_-]/g, '_')}.json`);
  writeFileSync(file, bytes);

  // migrations_applied count (post-run; the dump already includes the
  // migrations ledger rows themselves).
  const migrations = await applyMigrations(pool);

  const recordId = `BKP_${Date.now().toString(36).toUpperCase().padStart(6, '0')}`;
  await pool.query(
    `INSERT INTO backup_records (id, label, file_path, sha256, size_bytes, migrations_applied)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [recordId, label, file, sha256File(bytes), bytes.length, migrations],
  );
  console.log(`[backup] wrote ${file} (${bytes.length} bytes, sha256 ${sha256File(bytes).slice(0, 16)}…)`);
  console.log(`[backup] ${dump.tables.length} tables, ${dump.tables.reduce((acc, t) => acc + t.row_count, 0)} rows`);
  console.log(`[backup] record ${recordId} — verify with: npx tsx scripts/ops/restore.ts ${file}`);
} finally {
  await pool.end();
}
