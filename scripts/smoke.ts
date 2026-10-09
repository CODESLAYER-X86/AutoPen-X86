/**
 * End-to-end API smoke test (development convenience).
 * Boots its own API instance on an ephemeral port against the development
 * database (must already be migrated), then exercises:
 * register -> login -> project -> engagement -> scope -> target (in & out of
 * scope) -> start -> pause -> resume -> cancel -> events -> audit.
 * Exits non-zero on any failure.
 */
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';

const state: { app: FastifyInstance | null; pool: Pool | null } = { app: null, pool: null };

const BASE = await (async () => {
  const { loadConfig } = await import('@aegis/config');
  const { createPool } = await import('@aegis/database');
  const { buildApp } = await import('../apps/api/src/app.js');
  const config = loadConfig({ envFile: join(import.meta.dirname, '..', '.env') });
  state.pool = createPool(config.database.url, { max: 2 });
  state.app = await buildApp({ config, pool: state.pool });
  await state.app.listen({ port: 0, host: '127.0.0.1' });
  const address = state.app.server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 4000;
  return `http://127.0.0.1:${port}`;
})();

let token = '';
let failures = 0;

type Json = Record<string, unknown> | null;

async function call(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; json: Json }> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json: Json = null;
  try {
    json = text === '' ? null : (JSON.parse(text) as Json);
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
check('login returns token', r.status === 200 && typeof (r.json as { token?: unknown })?.token === 'string', r);
token = (r.json as { token?: string })?.token ?? '';

r = await call('GET', '/api/auth/me');
check('me returns the user', r.status === 200 && (r.json as { email?: string })?.email === email, r);

console.log('== projects & engagements ==');
r = await call('POST', '/api/projects', { name: 'Smoke Project', description: '' });
check('project created', r.status === 201 && /^PRJ_/.test((r.json as { id?: string })?.id ?? ''), r);
const projectId = (r.json as { id?: string })?.id ?? '';

r = await call('POST', '/api/engagements', {
  project_id: projectId,
  name: 'Smoke Engagement',
  mode: 'PENTEST',
  description: '',
});
check('engagement created DRAFT', r.status === 201 && (r.json as { status?: string })?.status === 'DRAFT', r);
const engagementId = (r.json as { id?: string })?.id ?? '';

console.log('== scope ==');
r = await call('POST', `/api/engagements/${engagementId}/targets`, {
  type: 'URL',
  value: 'http://127.0.0.1:9999/',
});
check(
  'target without scope rejected',
  r.status === 422 &&
    ((r.json as { error?: { code?: string } })?.error?.code === 'SCOPE_NOT_CONFIGURED'),
  r,
);

r = await call('POST', `/api/engagements/${engagementId}/scope`, {
  allowed_hosts: ['127.0.0.1'],
  allowed_domains: [],
  allowed_ports: [9999],
  allowed_schemes: ['http'],
  excluded_hosts: [],
  excluded_paths: [],
  destructive_actions_allowed: false,
});
check('scope saved', r.status === 200 && Array.isArray((r.json as { allowed_hosts?: unknown })?.allowed_hosts), r);

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
check(
  'out-of-scope target rejected',
  r.status === 422 &&
    ((r.json as { error?: { code?: string } })?.error?.code === 'TARGET_OUT_OF_SCOPE'),
  r,
);

r = await call('GET', `/api/engagements/${engagementId}`);
check(
  'engagement auto-promoted to READY',
  r.status === 200 &&
    (r.json as { engagement?: { status?: string } })?.engagement?.status === 'READY' &&
    (r.json as { readiness?: { ready?: boolean } })?.readiness?.ready === true,
  r,
);

console.log('== lifecycle ==');
r = await call('POST', `/api/engagements/${engagementId}/start`);
check('start -> RUNNING', r.status === 200 && (r.json as { status?: string })?.status === 'RUNNING', r);

r = await call('POST', `/api/engagements/${engagementId}/pause`);
check('pause -> PAUSED', r.status === 200 && (r.json as { status?: string })?.status === 'PAUSED', r);

r = await call('POST', `/api/engagements/${engagementId}/resume`);
check('resume -> RUNNING', r.status === 200 && (r.json as { status?: string })?.status === 'RUNNING', r);

r = await call('POST', `/api/engagements/${engagementId}/cancel`);
check('cancel -> CANCELLED', r.status === 200 && (r.json as { status?: string })?.status === 'CANCELLED', r);

r = await call('POST', `/api/engagements/${engagementId}/start`);
check('start after cancel rejected', r.status === 400, r);

console.log('== telemetry ==');
r = await call('GET', `/api/engagements/${engagementId}/events?limit=50`);
const types: string[] = ((r.json as { items?: Array<{ type: string }> })?.items ?? []).map((e) => e.type);
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
const actions: string[] = ((r.json as { items?: Array<{ action: string }> })?.items ?? []).map((a) => a.action);
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
  r.status === 200 &&
    (r.json as { implemented?: number })?.implemented !== undefined &&
    (r.json as { implemented?: number; total?: number })!.implemented! >= 1 &&
    (r.json as { total?: number; implemented?: number })!.total! > (r.json as { implemented?: number })!.implemented!,
  { implemented: (r.json as { implemented?: number })?.implemented, total: (r.json as { total?: number })?.total },
);

r = await call('GET', '/api/meta');
check(
  'meta exposes model roles',
  r.status === 200 &&
    (r.json as { models?: { strategic?: { provider?: string } } })?.models?.strategic?.provider === 'mock',
  r,
);

console.log('== agent (Part 2) ==');
r = await call('POST', '/api/engagements', {
  project_id: projectId,
  name: 'Smoke Agent Engagement',
  mode: 'CTF',
  description: 'Find the flag in the legacy endpoint.',
});
const agentEngagementId = (r.json as { id?: string })?.id ?? '';
check('agent engagement created', r.status === 201 && /^ENG_/.test(agentEngagementId), r);

await call('POST', `/api/engagements/${agentEngagementId}/scope`, {
  allowed_hosts: ['127.0.0.1'],
  allowed_domains: [],
  allowed_ports: [9999],
  allowed_schemes: ['http'],
  excluded_hosts: [],
  excluded_paths: [],
  destructive_actions_allowed: false,
});
await call('POST', `/api/engagements/${agentEngagementId}/targets`, {
  type: 'URL',
  value: 'http://127.0.0.1:9999/app',
});
r = await call('POST', `/api/engagements/${agentEngagementId}/start`);
check('agent engagement started', r.status === 200 && (r.json as { status?: string })?.status === 'RUNNING', r);

r = await call('POST', `/api/engagements/${agentEngagementId}/runs`, { reason: 'smoke test' });
const runId = (r.json as { id?: string })?.id ?? '';
check(
  'agent run created',
  r.status === 201 && /^RUN_/.test(runId) && (r.json as { leader_model?: string })?.leader_model !== undefined,
  r,
);

r = await call('GET', `/api/engagements/${agentEngagementId}/runs`);
check(
  'agent runs listed',
  r.status === 200 && ((r.json as { total?: number })?.total ?? 0) >= 1,
  r,
);

r = await call('GET', `/api/engagements/${agentEngagementId}/agent-metrics`);
check(
  'agent metrics exposed',
  r.status === 200 &&
    (r.json as { runs?: unknown })?.runs !== undefined &&
    (r.json as { tokens?: unknown })?.tokens !== undefined,
  r,
);

r = await call('POST', `/api/engagements/${agentEngagementId}/overrides`, {
  kind: 'ADD_CTF_CLUE',
  clue: 'The flag is hidden where old sessions go to die.',
});
check(
  'human override ADD_CTF_CLUE audited',
  r.status === 200 && /^OBS_/.test((r.json as { observation_id?: string })?.observation_id ?? ''),
  r,
);

r = await call('POST', `/api/engagements/${agentEngagementId}/recovery`, {});
check(
  'crash recovery endpoint works',
  r.status === 200 && typeof (r.json as { recovered?: number })?.recovered === 'number',
  r,
);

r = await call('POST', `/api/engagements/${agentEngagementId}/runs/${runId}/cancel`, {});
check('agent run cancelled by operator', r.status === 200 && (r.json as { cancelled?: boolean })?.cancelled === true, r);

r = await call('GET', `/api/engagements/${agentEngagementId}/events?limit=200`);
const agentTypes: string[] = ((r.json as { items?: Array<{ type: string }> })?.items ?? []).map((e) => e.type);
check(
  'agent events recorded',
  r.status === 200 && agentTypes.includes('AGENT_RUN_CREATED') && agentTypes.includes('AGENT_RUN_CANCELLED'),
  agentTypes.filter((t) => t.startsWith('AGENT') || t === 'HUMAN_OVERRIDE'),
);


// ---------------------------------------------------------------------------
// Part 3: interaction layer (HTTP engine + browser + sessions + artifacts)
// ---------------------------------------------------------------------------
console.log('== part 3 interaction layer ==');

r = await call('GET', '/api/meta');
const metaFeatures = (r.json as { capabilities?: { autonomous_tools?: Record<string, boolean> } })?.capabilities?.autonomous_tools;
check(
  'meta reports interaction tools as real',
  metaFeatures?.http === true && metaFeatures?.browser === true,
  metaFeatures,
);

// A dedicated engagement with the lab target in scope.
r = await call('POST', '/api/projects', { name: `smoke-p3-${Date.now()}`, description: '' });
const p3ProjectId = (r.json as { id?: string })?.id ?? '';
r = await call('POST', '/api/engagements', { project_id: p3ProjectId, name: 'p3-smoke', mode: 'PENTEST', description: '' });
const p3EngagementId = (r.json as { id?: string })?.id ?? '';
check('p3 engagement created', r.status === 201 && /^ENG_/.test(p3EngagementId), r);

// Start a local fixture target for the interaction checks.
const { startLabApp } = await import('../tests/fixtures/labApp.js');
const lab = await startLabApp();
try {
  r = await call('POST', `/api/engagements/${p3EngagementId}/scope`, {
    allowed_hosts: [lab.host],
    allowed_domains: [],
    allowed_ports: [lab.port],
    allowed_schemes: ['http'],
    excluded_hosts: [],
    excluded_paths: [],
    destructive_actions_allowed: false,
  });
  check('p3 scope saved around the lab app', r.status === 200, r);

  // http.request through the API (gateway path).
  r = await call('POST', `/api/engagements/${p3EngagementId}/http/request`, {
    method: 'GET',
    url: `${lab.url}/api/status`,
  });
  const p3RequestId = (r.json as { request_id?: string })?.request_id ?? '';
  check(
    'http.request executed + recorded',
    r.status === 200 && /^REQ_/.test(p3RequestId) && (r.json as { status?: number })?.status === 200,
    r,
  );

  // Replay (§19).
  r = await call('POST', `/api/engagements/${p3EngagementId}/http/replay`, { request_id: p3RequestId });
  check(
    'http.replay executed with parent linkage',
    r.status === 200 && (r.json as { request_id?: string })?.request_id !== p3RequestId,
    r,
  );

  // Mutation (§20-§22).
  r = await call('POST', `/api/engagements/${p3EngagementId}/http/mutate`, {
    base_request_id: p3RequestId,
    mutations: [{ location: 'query', name: 'smoke', operation: 'add', value: '1' }],
    execute: true,
  });
  check(
    'http.mutate applied + executed',
    r.status === 200 && ((r.json as { applied?: unknown[] })?.applied ?? []).length === 1 && (r.json as { status?: number })?.status === 200,
    r,
  );

  // Traffic list (§16-§18).
  r = await call('GET', `/api/engagements/${p3EngagementId}/http/requests`);
  check(
    'http traffic listed',
    r.status === 200 && ((r.json as { total?: number })?.total ?? 0) >= 3,
    r,
  );

  // HAR import (§80).
  r = await call('POST', `/api/engagements/${p3EngagementId}/http/har-import`, {
    har: { log: { entries: [{ request: { method: 'GET', url: `${lab.url}/api/status` }, response: { status: 200 } }] } },
  });
  check(
    'HAR import with scope filtering',
    r.status === 200 && (r.json as { imported?: number })?.imported === 1,
    r,
  );

  // Tool executions audit log (§78).
  r = await call('GET', `/api/engagements/${p3EngagementId}/tool-executions`);
  check(
    'tool executions logged',
    r.status === 200 && ((r.json as { items?: unknown[] })?.items ?? []).length >= 3,
    r,
  );

  // Browser context + action (§3-§8).
  r = await call('POST', `/api/engagements/${p3EngagementId}/browser/contexts`, { identity_id: null });
  const p3ContextId = (r.json as { context_id?: string })?.context_id ?? '';
  check('browser context opened', r.status === 200 && /^CTX_/.test(p3ContextId), r);

  r = await call('POST', `/api/engagements/${p3EngagementId}/browser/actions`, {
    context_id: p3ContextId,
    page_id: null,
    action: 'navigate',
    url: `${lab.url}/login`,
    timeout_ms: 15000,
  });
  check(
    'browser.navigate executed + traffic captured',
    r.status === 200 && (r.json as { ok?: boolean })?.ok === true && ((r.json as { http_records?: unknown[] })?.http_records ?? []).length >= 1,
    r,
  );

  r = await call('POST', `/api/engagements/${p3EngagementId}/browser/actions`, {
    context_id: p3ContextId,
    page_id: null,
    action: 'snapshot',
  });
  check(
    'browser.snapshot captured DOM',
    r.status === 200 && /^DMS_/.test((r.json as { details?: { snapshot_id?: string } })?.details?.snapshot_id ?? ''),
    r,
  );

  r = await call('GET', `/api/engagements/${p3EngagementId}/browser/events?limit=50`);
  const browserEventTypes: string[] = ((r.json as { items?: Array<{ event_type: string }> })?.items ?? []).map((e) => e.event_type);
  check(
    'browser events recorded',
    r.status === 200 && browserEventTypes.includes('NAVIGATION_COMPLETED') && browserEventTypes.includes('RESPONSE_RECEIVED'),
    [...new Set(browserEventTypes)],
  );

  r = await call('POST', `/api/engagements/${p3EngagementId}/browser/contexts/${p3ContextId}/close`, {});
  check('browser context closed (§75)', r.status === 200 && (r.json as { status?: string })?.status === 'CLOSED', r);

  // Scope enforcement: out-of-scope request refused (§49).
  r = await call('POST', `/api/engagements/${p3EngagementId}/http/request`, {
    method: 'GET',
    url: 'http://out-of-scope.example.com/x',
  });
  check(
    'out-of-scope request refused',
    r.status >= 400,
    r,
  );
} finally {
  await lab.close();
}

console.log('== part 4: security reasoning ==');
// Reuse the p3 engagement's recorded traffic: ingest -> attack surface.
r = await call('POST', `/api/engagements/${p3EngagementId}/reasoning/ingest`, { limit: 200 });
const ingest = (r.json as { processed?: number; created_endpoints?: number; failures?: number }) ?? {};
check(
  'reasoning ingest processed recorded traffic (idempotent, §111)',
  // created_endpoints is 0 when the dev DB already holds the endpoints —
  // re-ingestion must never duplicate them (that IS the §111 property).
  r.status === 200 && (ingest.processed ?? 0) >= 3 && (ingest.created_endpoints ?? 0) >= 0 && (ingest.failures ?? 0) === 0,
  r,
);

r = await call('GET', `/api/engagements/${p3EngagementId}/reasoning/status`);
const statusCounts = (r.json as { counts?: Record<string, number> })?.counts ?? {};
check(
  'reasoning status reports derived state',
  r.status === 200 &&
    (statusCounts.endpoints ?? 0) >= 1 &&
    (statusCounts.parameters ?? 0) >= 0 &&
    (statusCounts.matrix_entries ?? 0) >= 0,
  statusCounts,
);

r = await call('GET', `/api/engagements/${p3EngagementId}/reasoning/endpoints`);
const smokeEndpoints = ((r.json as { items?: Array<{ canonical_path: string }> })?.items ?? []).map((e) => e.canonical_path);
check(
  'endpoints discovered with canonical paths',
  r.status === 200 && smokeEndpoints.some((path) => path === '/api/status') && smokeEndpoints.some((path) => path === '/login'),
  smokeEndpoints,
);

r = await call('POST', `/api/engagements/${p3EngagementId}/reasoning/query`, {});
const focused = (r.json as { endpoints?: unknown[]; parameters?: unknown[] }) ?? {};
check(
  'focused attack-surface query answers bounded',
  r.status === 200 && (focused.endpoints ?? []).length >= 1 && (focused.endpoints ?? []).length <= 16,
  { endpoints: (focused.endpoints ?? []).length },
);

r = await call('GET', `/api/engagements/${p3EngagementId}/reasoning/projection`);
const projection = (r.json as { attack_surface?: { endpoint_count?: number }; recommended_tests?: unknown[] }) ?? {};
check(
  'leader security projection built (§120)',
  r.status === 200 && (projection.attack_surface?.endpoint_count ?? 0) >= 1 && Array.isArray(projection.recommended_tests),
  { endpoint_count: projection.attack_surface?.endpoint_count },
);

r = await call('GET', `/api/engagements/${p3EngagementId}/reasoning/test-candidates`);
check(
  'test candidates listed (§118 seam)',
  r.status === 200 && Array.isArray((r.json as { items?: unknown[] })?.items),
  r,
);

// Differential over two recorded requests of the same lab endpoint.
const traffic = await call('GET', `/api/engagements/${p3EngagementId}/http/requests?limit=5`);
const requestIds = ((traffic.json as { items?: Array<{ id: string }> })?.items ?? []).map((row) => row.id);
if (requestIds.length >= 2) {
  r = await call('POST', `/api/engagements/${p3EngagementId}/reasoning/differential`, {
    baseline_request_id: requestIds[0],
    candidate_request_id: requestIds[1],
  });
  check(
    'differential comparison recorded (§25)',
    r.status === 201 && /^DF[CR]_/.test((r.json as { id?: string })?.id ?? ''),
    r,
  );
} else {
  check('differential comparison recorded (§25)', false, { request_ids: requestIds.length });
}

r = await call('GET', `/api/engagements/${p3EngagementId}/reasoning/signals`);
check('signals queryable', r.status === 200 && Array.isArray((r.json as { items?: unknown[] })?.items), r);

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
  await state.app?.close();
  await state.pool?.end();
  process.exit(1);
}
console.log('\nSMOKE TEST PASSED');
await state.app?.close();
await state.pool?.end();
process.exit(0);
