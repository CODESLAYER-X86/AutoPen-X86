/** Stop the embedded PostgreSQL cluster. */
import { existsSync } from 'node:fs';
import { PG_DATA_DIR, isPostgresRunning, stopCluster } from './common.js';

if (!existsSync(PG_DATA_DIR)) {
  console.log('[db] no cluster initialised');
} else if (await isPostgresRunning()) {
  stopCluster();
  console.log('[db] postgres stopped');
} else {
  console.log('[db] postgres not running');
}
