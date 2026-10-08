/** Start the embedded PostgreSQL cluster (initialising on first run). */
import { ensureRunning, isPostgresRunning } from './common.js';

const already = await isPostgresRunning();
await ensureRunning();
console.log(already ? '[db] postgres already running' : '[db] postgres started');
