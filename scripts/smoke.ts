/**
 * End-to-end API smoke test (development convenience).
 * Boots its own API instance on an ephemeral port against the development
 * database (must already be migrated), then exercises:
 * register -> login -> project -> engagement -> scope -> target (in & out of
 * scope) -> start -> pause -> resume -> cancel -> events -> audit.
 * Exits non-zero on any failure.
 */
import { join } from 'node:path';

let app: import('fastify').FastifyInstance | null = null;
let pool: import('pg').Pool | null = null;

const BASE = await (async () => {
  const { loadConfig } = await import('@aegis/config');
  const { createPool } = await import('@aegis/database');
  const { buildApp } = await import('../apps/api/src/app.js');
  const config = loadConfig({ envFile: join(import.meta.dirname, '..', '.env') });
  pool = createPool(config.database.url, { max: 2 });
  app = await buildApp({ config, pool });
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 4000;
  return `http://127.0.0.1:${port}`;
})();

let token = '';
let failures = 0;

async function call(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: any }> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json: any = null;
  try {
    json = text === '' ? null : JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: response.status, json };
}

function check(name: string, condition: boolean, context?: unknown): void {
  if (condition) {
    console.log(`  ✓ ${name}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${name}`, JSON.stringify(context ?? {}, null, 2));
  }
}

const email = `smoke-${Date.now()}@test.local`;

console.log('== auth ==');
let r = await call('POST', '/api/auth/register', {
  email,
  name: 'Smoke Tester',
  password: 'password1234',
});
check('register returns 201', r.status === 201, r);

r = await call('POST', '/api/auth/login', { email, password: 'password1234' });
check('login returns token', r.status === 200 && typeof r.json?.token === 'string', r);
token = r.json?.token ?? '';

r = await call('GET', '/api/auth/me');
check('me returns the user', r.status === 200 && r.json?.email === email, r);

console.log('== projects & engagements ==');
r = await call('POST', '/api/projects', { name: 'Smoke Project', description: '' });
check('project created', r.status === 201 && /^PRJ_/.test(r.json?.id ?? ''), r);
const projectId = r.json?.id;

r = await call('POST', '/api/engagements', {
  project_id: projectId,
  name: 'Smoke Engagement',
  mode: 'PENTEST',
  description: '',
});
check('engagement created DRAFT', r.status === 201 && r.json?.status === 'DRAFT', r);
const engagementId = r.json?.id;

console.log('== scope ==');
r = await call('POST', `/api/engagements/${engagementId}/targets`, {
  type: 'URL',
  value: 'http://127.0.0.1:9999/',
});
check('target without scope rejected', r.status === 422 && r.json?.error?.code === 'SCOPE_NOT_CONFIGURED', r);

r = await call('POST', `/api/engagements/${engagementId}/scope`, {
  allowed_hosts: ['127.0.0.1'],
  allowed_domains: [],
  allowed_ports: [9999],
  allowed_schemes: ['http'],
  excluded_hosts: [],
  excluded_paths: [],
  destructive_actions_allowed: false,
});
check('scope saved', r.status === 200 && Array.isArray(r.json?.allowed_hosts), r);

console.log('== targets ==');
r = await call('POST', `/api/engagements/${engagementId}/targets`, {
  type: 'URL',
  value: 'http://127.0.0.1:9999/app',
});
check('in-scope target accepted', r.status === 201, r);

r = await call('POST', `/api/engagements/${engagementId}/targets`, {
  type: 'URL',
  value: 'http://evil.example.com/',
});
check('out-of-scope target rejected', r.status === 422 && r.json?.error?.code === 'TARGET_OUT_OF_SCOPE', r);

r = await call('GET', `/api/engagements/${engagementId}`);
check(
  'engagement auto-promoted to READY',
  r.status === 200 && r.json?.engagement?.status === 'READY' && r.json?.readiness?.ready === true,
  r,
);

console.log('== lifecycle ==');
r = await call('POST', `/api/engagements/${engagementId}/start`);
check('start -> RUNNING', r.status === 200 && r.json?.status === 'RUNNING', r);

r = await call('POST', `/api/engagements/${engagementId}/pause`);
check('pause -> PAUSED', r.status === 200 && r.json?.status === 'PAUSED', r);

r = await call('POST', `/api/engagements/${engagementId}/resume`);
check('resume -> RUNNING', r.status === 200 && r.json?.status === 'RUNNING', r);

r = await call('POST', `/api/engagements/${engagementId}/cancel`);
check('cancel -> CANCELLED', r.status === 200 && r.json?.status === 'CANCELLED', r);

r = await call('POST', `/api/engagements/${engagementId}/start`);
check('start after cancel rejected', r.status === 400, r);

console.log('== telemetry ==');
r = await call('GET', `/api/engagements/${engagementId}/events?limit=50`);
const types: string[] = (r.json?.items ?? []).map((e: { type: string }) => e.type);
check(
  'events recorded',
  r.status === 200 &&
    types.includes('ENGAGEMENT_CREATED') &&
    types.includes('SCOPE_UPDATED') &&
    types.includes('TARGET_ADDED') &&
    types.includes('TARGET_REJECTED') &&
    types.includes('ENGAGEMENT_STARTED'),
  types,
);

r = await call('GET', `/api/engagements/${engagementId}/audit?limit=50`);
const actions: string[] = (r.json?.items ?? []).map((a: { action: string }) => a.action);
check(
  'audit trail recorded',
  r.status === 200 &&
    actions.includes('ENGAGEMENT_CREATED') &&
    actions.includes('SCOPE_CHANGED') &&
    actions.includes('TARGET_ADDED') &&
    actions.includes('ENGAGEMENT_CANCELLED'),
  actions,
);

r = await call('GET', '/api/tools');
check(
  'tools list with implemented flags',
  r.status === 200 && r.json?.implemented >= 1 && r.json?.total > r.json?.implemented,
  { implemented: r.json?.implemented, total: r.json?.total },
);

r = await call('GET', '/api/meta');
check('meta exposes model roles', r.status === 200 && r.json?.models?.strategic?.provider === 'mock', r);

console.log('== security headers ==');
const response = await fetch(`${BASE}/api/meta`);
check(
  'security headers present',
  response.headers.get('x-content-type-options') === 'nosniff' &&
    response.headers.get('x-frame-options') === 'DENY',
  {
    nosniff: response.headers.get('x-content-type-options'),
    frame: response.headers.get('x-frame-options'),
  },
);

if (failures > 0) {
  console.error(`\nSMOKE TEST FAILED: ${failures} failure(s)`);
  await app?.close();
  await pool?.end();
  process.exit(1);
}
console.log('\nSMOKE TEST PASSED');
await app?.close();
await pool?.end();
process.exit(0);
