/** Destroy and rebuild the local cluster + databases + migrations. */
import { existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { createPool, runMigrations } from '@aegis/database';
import { loadConfig } from '@aegis/config';
import { PG_DATA_DIR, REPO_ROOT, ensureRunning, isPostgresRunning, stopCluster } from './common.js';

if (await isPostgresRunning()) {
  stopCluster();
}
if (existsSync(PG_DATA_DIR)) {
  rmSync(PG_DATA_DIR, { recursive: true, force: true });
}
await ensureRunning();

const config = loadConfig({ envFile: join(REPO_ROOT, '.env') });
const pool = createPool(config.database.url, { max: 2 });
try {
  const report = await runMigrations(pool, join(REPO_ROOT, 'packages', 'database', 'migrations'));
  console.log(`[reset] migrations applied: ${report.applied.length}`);
} finally {
  await pool.end();
}
