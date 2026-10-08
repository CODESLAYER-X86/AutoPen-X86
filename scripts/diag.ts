/** Quick diagnostic: exercise the app via fastify.inject. */
import { join } from 'node:path';
import { loadConfig } from '@aegis/config';
import { createPool } from '@aegis/database';
import { buildApp } from '../apps/api/src/app.js';

const config = loadConfig({ envFile: join(import.meta.dirname, '..', '.env') });
const pool = createPool(config.database.url, { max: 2 });
const app = await buildApp({ config, pool });

const injection = await app.inject({
  method: 'POST',
  url: '/api/auth/register',
  payload: { email: `diag-${Date.now()}@test.local`, name: 'Diag', password: 'password1234' },
});
console.log('register status:', injection.statusCode);
console.log('register body:', injection.body.slice(0, 300));

const meta = await app.inject({ method: 'GET', url: '/api/meta' });
console.log('meta status:', meta.statusCode, meta.body.slice(0, 120));

await app.close();
await pool.end();
console.log('DONE');
process.exit(0);
