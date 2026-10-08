/** Ensure cluster + databases exist (used before tests and dev servers). */
import { ensureRunning } from './common.js';

await ensureRunning();
console.log('[db] ready');
