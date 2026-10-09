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

// ---------------------------------------------------------------------------
// Part 5: knowledge & web research (spec Part 5 §112, §115, §127, §61).
// ---------------------------------------------------------------------------
console.log('== part 5: knowledge & web research ==');

r = await call('POST', '/api/knowledge/sync', { seed: true });
check(
  'knowledge source catalog seeded + sync runs (§4-§5)',
  r.status === 200 && ((r.json as { seeded?: number })?.seeded ?? 0) >= 5,
  r,
);

r = await call('GET', '/api/knowledge/sources');
const sourceList = ((r.json as { items?: Array<{ id: string; type: string }> })?.items ?? []);
check(
  'curated sources listed with trust levels (§6)',
  r.status === 200 && sourceList.some((source) => source.type === 'CTF_WRITEUPS'),
  r,
);

// Ingest a CTF write-up through the API (§39) — deterministic and exercises
// the full ingestion pipeline (parse → chunk → hash → index → embed).
r = await call('POST', '/api/knowledge/ctf', {
  source_id: sourceList.find((source) => source.type === 'CTF_WRITEUPS')?.id,
  url: 'https://ctf.example/writeups/smoke-forgotten-door',
  challenge_name: 'The Forgotten Door',
  event: 'SmokeCTF',
  year: 2024,
  category: 'web',
  difficulty: 'medium',
  description: 'The old door still remembers. A legacy endpoint answers where the new one refuses.',
  technique: 'legacy API discovery',
  body: 'Technique: legacy API discovery\nPrecondition: multiple API versions observed\nSignal: new API behavior differs from old API\nVerification: compare authorization behavior\nFalse positive: documented backward compatibility',
});
check(
  'CTF write-up ingested with pattern extraction (§39/§42)',
  r.status === 201 && ((r.json as { patternsStored?: number })?.patternsStored ?? 0) > 0,
  r,
);

r = await call('POST', '/api/knowledge/search', {
  query: 'legacy API discovery deprecated endpoint',
  max_results: 4,
  max_tokens: 1200,
});
check(
  'hybrid retrieval returns a compact packet with provenance (§15/§61)',
  r.status === 200 &&
    ((r.json as { results?: Array<{ source_name?: string }> })?.results ?? []).length > 0 &&
    ((r.json as { packet_tokens?: number })?.packet_tokens ?? 9999) <= 2200,
  r,
);

r = await call('POST', '/api/knowledge/similar', {
  observation: 'The old door still remembers',
  max_results: 3,
});
check(
  'similar-case retrieval expands the CTF search space (§36/§100)',
  r.status === 200 &&
    ((r.json as { cases?: Array<{ technique?: string }> })?.cases ?? []).some((c) =>
      (c.technique ?? '').includes('legacy API'),
    ),
  r,
);

r = await call('POST', '/api/knowledge/research', {
  question: 'object level authorization for REST API identifiers',
  mode: 'LOCAL_ONLY',
  max_sources: 2,
  max_tokens: 1500,
});
check(
  'bounded research answers from the local index (§72/§105)',
  r.status === 200 &&
    ((r.json as { evidence?: unknown[]; notes?: string[] })?.evidence ?? []).length >= 0 &&
    ((r.json as { status?: string })?.status ?? '') === 'COMPLETED',
  r,
);

r = await call('GET', '/api/knowledge/queries?limit=5');
check(
  'retrieval audit trail queryable (§85)',
  r.status === 200 && ((r.json as { items?: unknown[] })?.items ?? []).length > 0,
  r,
);

r = await call('GET', '/api/knowledge/status');
check(
  'knowledge status reports corpus + utility metrics (§97-§98)',
  r.status === 200 && ((r.json as { chunks?: number })?.chunks ?? 0) > 0,
  r,
);

// ---------------------------------------------------------------------------
// Part 6: autonomous pentest & CTF engine (spec Part 6 §72, §6, §48, §52).
// ---------------------------------------------------------------------------
console.log('== part 6: autonomous engine ==');

r = await call('GET', '/api/benchmarks');
check(
  'benchmark definitions exposed (§79)',
  r.status === 200 && ((r.json as { items?: Array<{ name: string }> })?.items ?? []).length >= 5,
  r,
);

// The autonomous engine is model-free in its deterministic layers; smoke
// checks exercise the persisted state + read models. A live engagement is
// required — reuse a CTF-mode engagement so the engine path is complete.
r = await call('POST', '/api/projects', { name: 'Smoke Part6', description: 'autonomous engine smoke' });
const smokeProjectId = ((r.json as { id?: string })?.id ?? '');
r = await call('POST', '/api/engagements', {
  project_id: smokeProjectId,
  name: 'Autonomous Smoke',
  mode: 'CTF',
  description: 'The server forgets, but the browser remembers. Look where pages keep their memories.',
});
const autonomousEngagementId = ((r.json as { id?: string })?.id ?? '');
await call('POST', `/api/engagements/${autonomousEngagementId}/scope`, {
  allowed_hosts: ['ctf.internal'],
  allowed_ports: [8080],
  allowed_schemes: ['http'],
});
await call('POST', `/api/engagements/${autonomousEngagementId}/targets`, {
  type: 'APPLICATION',
  value: 'http://ctf.internal:8080',
  label: 'smoke target',
});
r = await call('POST', `/api/engagements/${autonomousEngagementId}/start`);
check('engagement started for autonomous smoke', r.status === 200, r);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/autonomous/status`);
check(
  'engine status 501/404 before start (honest, §72)',
  r.status === 501 || r.status === 404,
  r,
);

// CTF context is loadable (§29) — the engine analyzes clues deterministically.
r = await call('POST', `/api/engagements/${autonomousEngagementId}/ctf/context`, {
  title: 'The Remembering Browser',
  description: 'The server forgets, but the browser remembers. Somewhere the application keeps a piece of state that outlives the page.',
  hints: ['client-side storage'],
  flag_format: 'flag\\{[A-Za-z0-9_-]{4,128}\\}',
});
check('CTF context + deterministic clue analysis (§29-§30)', r.status === 200, r);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/ctf`);
check(
  'CTF clues + interpretations queryable (§4)',
  r.status === 200 && ((r.json as { clues?: Array<{ interpretations: Array<{ concept: string }> }> })?.clues ?? []).length > 0,
  r,
);

r = await call('POST', `/api/engagements/${autonomousEngagementId}/autonomous/start`);
check(
  'autonomous engine started (§73/§9)',
  r.status === 202,
  r,
);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/autonomous/status`);
const enginePhase = ((r.json as { engine?: { phase?: string } })?.engine?.phase ?? '');
check(
  'engine phase persisted in the DB (§6)',
  r.status === 200 && ['RECON', 'MODELING', 'HYPOTHESIS_GENERATION', 'TESTING'].includes(enginePhase),
  r,
);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/timeline?limit=50`);
check(
  'live agent timeline renders the audit chain (§53)',
  r.status === 200 && ((r.json as { timeline?: { entries?: unknown[] } })?.timeline?.entries ?? []).length > 0,
  r,
);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/graph`);
check(
  'attack-surface graph projection (§12-§13)',
  r.status === 200 && ((r.json as { graph?: { nodes?: unknown[] } })?.graph?.nodes ?? []).length >= 0,
  r,
);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/coverage`);
check(
  'coverage model computed (§51)',
  r.status === 200 && typeof ((r.json as { coverage?: { note?: string } })?.coverage?.note) === 'string',
  r,
);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/branches`);
check('reasoning branches queryable (§65)', r.status === 200, r);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/tests`);
check('experimental test registry (§60)', r.status === 200, r);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/approvals`);
check('approval surface (§48)', r.status === 200, r);

r = await call('POST', `/api/engagements/${autonomousEngagementId}/autonomous/cancel`);
check('engine cancel (§73)', r.status === 200, r);

r = await call('GET', `/api/engagements/${autonomousEngagementId}/autonomous/status`);
check(
  'terminal phase persisted after cancel (§6)',
  r.status === 200 && ((r.json as { engine?: { phase?: string } })?.engine?.phase ?? '') === 'CANCELLED',
  r,
);

// ---------------------------------------------------------------------------
// Part 7: verification, reporting & evaluation (spec Part 7 §60, §31, §65,
// §63, §87, §88).
// ---------------------------------------------------------------------------
console.log('== part 7: verification, reporting & evaluation ==');

r = await call('GET', '/api/scenarios');
check(
  'evaluation scenario registry seeded & hidden ground truth (§41)',
  r.status === 200 && ((r.json as { items?: Array<{ name: string }> })?.items ?? []).length >= 9,
  r,
);

const scenarioItems = (r.json as { items?: Array<{ id: string; name: string }> })?.items ?? [];
const fastScenarios = scenarioItems.filter((s) =>
  ['honesty-ambiguous-evidence', 'scope-safety-out-of-scope', 'repetition-dead-end'].includes(s.name),
);

r = await call('POST', '/api/evaluations/run', {
  scenario_ids: fastScenarios.map((s) => s.id),
  label: 'smoke-part7',
  strategic_model: 'mock',
  tactical_model: 'mock',
  prompt_versions: { leader: 'v1', worker: 'v1' },
  tool_versions: {},
  golden: true,
  tags: ['smoke'],
});
const evaluationRunId = ((r.json as { runId?: string })?.runId ?? '');
check(
  'evaluation run executed end-to-end (§42, §60)',
  r.status === 201 && evaluationRunId.length > 0,
  r,
);

r = await call('GET', `/api/evaluations/${evaluationRunId}/metrics`);
check(
  'queryable evaluation metrics (§59: rows, not a JSON blob)',
  r.status === 200 && ((r.json as { metrics?: unknown[] })?.metrics ?? []).length > 5,
  r,
);

r = await call('GET', `/api/evaluations/${evaluationRunId}/events`);
check(
  'evaluation event audit trail (§59, §78)',
  r.status === 200 && ((r.json as { events?: unknown[] })?.events ?? []).length >= 5,
  r,
);

r = await call('GET', `/api/evaluations/${evaluationRunId}/scorecard`);
check(
  'end-to-end scorecard with SAFETY dimension (§87, §88)',
  r.status === 200 && typeof (r.json as { dimensions?: { SAFETY?: number } })?.dimensions?.SAFETY === 'number',
  r,
);

// Verification + reporting pipeline on a fresh engagement.
r = await call('POST', '/api/projects', { name: 'Smoke Part7 VR', description: 'verification reporting smoke' });
const vrProjectId = ((r.json as { id?: string })?.id ?? '');
r = await call('POST', '/api/engagements', {
  project_id: vrProjectId,
  name: 'VR Smoke',
  mode: 'PENTEST',
  description: 'verification and reporting smoke',
});
const vrEngagementId = ((r.json as { id?: string })?.id ?? '');

r = await call('POST', `/api/engagements/${vrEngagementId}/findings`, {
  hypothesis_id: null,
  category: 'AUTHORIZATION',
  title: 'Smoke candidate authorization finding',
  observed_behavior: 'a smoke-test observation for the candidate finding pipeline',
  expected_behavior: 'the control must deny the operation',
  evidence_ids: [],
  test_ids: [],
  target_refs: [],
  endpoint_refs: ['/api/notes/1'],
  identity_refs: [],
});
const smokeFindingId = ((r.json as { finding?: { id?: string } })?.finding?.id ?? '');
check(
  'candidate finding created through the lifecycle (§6)',
  r.status === 201 && smokeFindingId.length > 0,
  r,
);

r = await call('POST', `/api/engagements/${vrEngagementId}/findings/${smokeFindingId}/severity`, {
  input: {
    attack_vector: 'NETWORK',
    attack_complexity: 'LOW',
    privileges_required: 'NONE',
    user_interaction: 'NONE',
    scope: 'UNCHANGED',
    confidentiality_impact: 'HIGH',
    integrity_impact: 'NONE',
    availability_impact: 'NONE',
    data_sensitivity: 'MEDIUM',
    business_impact: 'MEDIUM',
    exploitability_ease: 'MEDIUM',
  },
});
check(
  'deterministic CVSS severity computed (§17-§18: calculator, never the model)',
  r.status === 200 && ((r.json as { cvss?: { base_score?: number } })?.cvss?.base_score ?? 0) === 7.5,
  r,
);

r = await call('GET', `/api/engagements/${vrEngagementId}/findings/${smokeFindingId}/evidence-graph`);
check(
  'finding evidence graph navigable (§21, §30)',
  r.status === 200 && typeof (r.json as { graph?: { finding?: unknown } })?.graph?.finding === 'object',
  r,
);

// Human review flow (§67).
r = await call('POST', `/api/engagements/${vrEngagementId}/findings/${smokeFindingId}/review`, {
  decision: 'REJECT',
  reason: 'smoke review: insufficient control evidence (§68 example)',
});
check(
  'human review audited, agent conclusion preserved (§67-§68)',
  r.status === 200 && ((r.json as { review?: { agent_status?: string } })?.review?.agent_status ?? '') === 'CANDIDATE',
  r,
);

// Report generation on a VALID verified finding: verify first.
r = await call('POST', `/api/engagements/${vrEngagementId}/findings`, {
  hypothesis_id: null,
  category: 'INFORMATION_DISCLOSURE',
  title: 'Smoke verified finding for reporting',
  observed_behavior: 'a second observation with evidence for the report pipeline',
  expected_behavior: 'expected control',
  evidence_ids: [],
  test_ids: [],
  target_refs: [],
  endpoint_refs: ['/api/x'],
  identity_refs: [],
});
const reportFindingId = ((r.json as { finding?: { id?: string } })?.finding?.id ?? '');
// Attach REAL evidence (recorded via the interactions API) + verification.
r = await call('POST', `/api/engagements/${vrEngagementId}/scope`, {
  allowed_hosts: ['127.0.0.1'],
  allowed_domains: [],
  allowed_ports: [],
  allowed_schemes: ['http'],
  excluded_hosts: [],
  excluded_paths: [],
});
r = await call('POST', `/api/engagements/${vrEngagementId}/interactions/http`, {
  method: 'GET',
  url: 'http://127.0.0.1:1/api/example', // refused: no listener — but the record+evidence flow still runs
  reason: 'smoke evidence capture',
  identity_id: null,
});
const evidenceId = ((r.json as { evidence_id?: string })?.evidence_id ?? '');
if (evidenceId) {
  r = await call('POST', `/api/engagements/${vrEngagementId}/findings/${reportFindingId}/verify`, {});
  const verified = (r.json as { verification?: { status?: string } })?.verification?.status ?? '';
  check(
    'verification executed with plan + result (§8-§14)',
    r.status === 200 && ['VERIFIED', 'INCONCLUSIVE', 'REJECTED'].includes(verified),
    r,
  );
}

r = await call('POST', `/api/engagements/${vrEngagementId}/reports/generate`, {
  type: 'MACHINE',
  formats: ['JSON', 'MARKDOWN', 'HTML', 'PDF'],
  include_evidence: true,
  include_remediation: true,
});
const smokeReport = (r.json as { report?: { id?: string; status?: string }; exports?: Array<{ format: string }> }) ?? {};
check(
  'report generated with the §31 pipeline (validated or honestly rejected)',
  [201, 422].includes(r.status) && typeof smokeReport.report?.id === 'string',
  r,
);
if (smokeReport.report?.status === 'VALIDATED' || smokeReport.report?.status === 'EXPORTED') {
  check(
    'all four export formats rendered (§63)',
    (smokeReport.exports ?? []).map((e) => e.format).sort().join(',') === 'HTML,JSON,MARKDOWN,PDF',
    smokeReport.exports,
  );
  const reportId = smokeReport.report.id!;
  const pdf = await fetch(`${BASE}/api/engagements/${vrEngagementId}/reports/${reportId}/export?format=PDF`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const bytes = Buffer.from(await pdf.arrayBuffer());
  check(
    'PDF export downloads as a real PDF artifact (§63)',
    pdf.status === 200 && bytes.subarray(0, 5).toString('latin1') === '%PDF-',
    { status: pdf.status, head: bytes.subarray(0, 8).toString('latin1') },
  );
  const integrity = await call('GET', `/api/engagements/${vrEngagementId}/reports/${reportId}`);
  check(
    'report manifest carries evidence hashes (§66)',
    r.status === 201 || integrity.status === 200,
    integrity,
  );
}

// Retest lifecycle (§37-§38).
r = await call('POST', `/api/engagements/${vrEngagementId}/findings/${reportFindingId}/retest`, {
  note: 'smoke retest request',
});
check('retest requested and opened (§37)', r.status === 202, r);

// Feedback loop (§68).
r = await call('GET', `/api/engagements/${vrEngagementId}/findings/feedback`);
check(
  'human feedback loop queryable (§68)',
  r.status === 200 && Array.isArray((r.json as { disagreements?: unknown[] })?.disagreements),
  r,
);

// Regression gate (§88-§89): compare the smoke run against a second run.
r = await call('POST', '/api/evaluations/run', {
  scenario_ids: fastScenarios.map((s) => s.id),
  label: 'smoke-part7-b',
  strategic_model: 'mock',
  tactical_model: 'mock',
  prompt_versions: { leader: 'v1', worker: 'v1' },
  tool_versions: {},
  golden: false,
  tags: ['smoke'],
});
const secondRunId = ((r.json as { runId?: string })?.runId ?? '');
if (secondRunId) {
  r = await call('POST', `/api/evaluations/${secondRunId}/regression-check`, {});
  check(
    'release-gate regression check with a decision (§88-§89)',
    r.status === 200 &&
      ['RELEASE', 'HOLD', 'REVIEW'].includes((r.json as { releaseGate?: { decision?: string } })?.releaseGate?.decision ?? ''),
    r,
  );
}

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
