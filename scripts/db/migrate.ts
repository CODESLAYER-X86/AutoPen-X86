/** Apply all pending migrations to the development database. */
import { join } from 'node:path';
import { createPool, runMigrations } from '@aegis/database';
import { loadConfig } from '@aegis/config';
import { REPO_ROOT } from './common.js';

const config = loadConfig({ envFile: join(REPO_ROOT, '.env') });
const pool = createPool(config.database.url, { max: 2 });
try {
  const report = await runMigrations(pool, join(REPO_ROOT, 'packages', 'database', 'migrations'));
  console.log(`[migrate] applied ${report.applied.length}, skipped ${report.skipped.length}`);
  if (report.applied.length > 0) {
    for (const name of report.applied) console.log(`  + ${name}`);
  }
} finally {
  await pool.end();
}
