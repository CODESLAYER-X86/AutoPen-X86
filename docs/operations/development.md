# Development Operations

## Prerequisites

* Node.js >= 20 (tested on 24)
* npm >= 10
* No root required: PostgreSQL binaries come from the `embedded-postgres`
  dev dependency (a real postgres server, run as your own user)

## First start

```bash
npm install                       # installs all workspaces + PG binaries
cp .env.example .env              # adjust if needed
npm run db:ensure                 # init + start PG on 127.0.0.1:5433, create DBs
npm run db:migrate                # apply migrations to the dev database
npm run dev:api                   # API on :4000 (tsx watch)
# second terminal:
npm run dev:web                   # UI on :5173 with /api proxy to :4000
```

Open http://localhost:5173, create an account, a project, an engagement,
configure the scope, add a target.

## Database lifecycle

```bash
npm run db:start     # start embedded PostgreSQL (initialises on first run)
npm run db:stop      # fast shutdown
npm run db:ensure    # start if needed + ensure databases exist (used by tests)
npm run db:migrate   # apply pending migrations (hash-verified, idempotent)
npm run db:reset     # destroy + rebuild cluster, databases, migrations
```

Connection strings live in `.env` (`DATABASE_URL`, `TEST_DATABASE_URL`).
In development the `.env` file takes precedence over stray shell variables
(see `docs` note in `packages/config`); in production a `.env` file is
refused — set real environment variables.

## Quality gates

```bash
npm run typecheck            # tsc -b (all packages/services/api) + tests + scripts + web
npm run lint                 # eslint over the monorepo
npm run test                 # db:ensure + unit + integration + security + e2e
npm run test:unit            # 128 tests, no database needed
npm run test:integration     # 44 tests against aegis_test
npm run test:security        # 28 tests (authz, secrets-in-logs, scope bypass…)
npm run test:e2e             # 2 tests over real HTTP + local mock target
npm run build                # server build + web production build
npx tsx scripts/smoke.ts     # 20-check end-to-end smoke test (dev DB)
```

All suites expect `npm run db:ensure` to have run (the `test` script does it
automatically). Tests are safe: they use the `aegis_test` database and a
local mock target server — no external network access (spec §34).

## Configuration

Everything is environment-driven and schema-validated at startup (fail
fast). See `.env.example` for the full list. Model roles
(`STRATEGIC_MODEL_PROVIDER/ID`, `TACTICAL_MODEL_PROVIDER/ID`) change without
code changes; `google` providers require `GOOGLE_API_KEY` in the environment.

## Project layout & docs

* `docs/architecture/` — overview, boundaries, data model, events
* `docs/security/threat-model.md`
* `docs/api/README.md`
* Worklog: `/home/z/my-project/worklog.md`

## Production notes (not the Part 1 dev path)

* Use a managed PostgreSQL and set `DATABASE_URL` (+ TLS) — do not ship `.env`
* Terminate TLS in front of the API; set `CORS_ORIGINS` explicitly
* Set `SECRET_STORE_MASTER_KEY` (base64, 32 bytes) instead of the dev key file
* Run `node apps/api/dist/server.js` after `npm run build`

---

# Development — Part 2 (Agent Operating System)

## Running the autonomous agent locally

1. `npm run dev:api` (migrations run automatically, including Part 2's
   013–027 agent tables).
2. `npm run dev:web`, log in, open an engagement, add scope + target, start
   the engagement, then use the **agent** tab → *Start agent run*.
3. With the default `mock` model providers the loop is fully exercised
   mechanically but the leader emits non-JSON decisions; the run will
   deterministically fail with `LEADER_DECISION_NOT_JSON`-style rejections
   (recorded as REJECTED decision cycles). That is the honest behaviour of a
   provider that is not a real model — set `STRATEGIC_MODEL_PROVIDER=google`
   (and `TACTICAL_MODEL_PROVIDER=google`) plus `GOOGLE_API_KEY` for real
   reasoning.
4. The mock providers can be scripted for deterministic simulations — see
   `tests/integration/agent-helpers.ts` (`createAgentTestContext`).

## Testing the agent OS

* Unit: state machines, priority scoring, fingerprints, quota, retry
  classification, policy, prompts, hypothesis transitions.
* Integration: the full §72 pipeline, the §73 autonomous simulation, §74
  quota simulations, §75 failure simulations, §63-§65 recovery, and the
  agent HTTP API.
* Security: prompt-injection labeling against REAL persisted agent messages,
  scope-bypass attempts through the worker tool path, and secret isolation.
* `npx tsx scripts/smoke.ts` exercises the agent endpoints end-to-end.

## Environment knobs

All agent tunables are documented in `.env.example` (`AGENT_*`): loop bounds,
worker limits, quota (RPM/TPM/RPD), per-purpose token budgets, and
engagement resource budget defaults.

## Part 3 — running the interaction layer

* **Playwright**: `services/browser` uses `playwright-core` with bundled
  Chromium. Install browsers once per host:
  `npx playwright-core install chromium` (downloads to `~/.cache/ms-playwright`).
  Launch args include `--no-sandbox` for container environments.
* **Feature flags**: `FEATURE_TOOLS_HTTP` / `FEATURE_TOOLS_BROWSER` (default
  on since Part 3) toggle registration of the interaction tools at
  composition time — the gateway then honestly reports TOOL_NOT_FOUND.
* **Network policy**: dev/test uses the lab policy (loopback allowed for
  fixture apps); production keeps the restrictive default. Scope must
  explicitly allow the target host AND port.
* **Session material**: register identity auth state via
  `POST /api/engagements/:id/browser/contexts/:cid/promote-session` or the
  session manager service; values go straight to the encrypted secret store.
* **Tests**: unit (§82 pure logic), integration (real Chromium + real HTTP
  against the local lab app in `tests/fixtures/labApp.ts`), security
  (§82.4 fail-closed cases). `npm run db:ensure` must run first.
* **HAR import**: `POST /api/engagements/:id/http/har-import` — entries are
  scope-filtered at import and re-validated at replay.

## Part 4 — security reasoning engine

* **Feature flag**: `FEATURE_SECURITY_REASONING` (default on). When off,
  reasoning routes answer 501 and the processor does not subscribe.
* **Ingestion**: event-driven as traffic is recorded (§109); a full
  deterministic backfill is available via
  `POST /api/engagements/:id/reasoning/ingest` (idempotent, §111).
* **Resource limits** (§113): `REASONING_MAX_*` env knobs (graph nodes,
  edges, signals, parameters, endpoints, comparison bytes).
* **Tests**: `tests/unit/part4-reasoning.test.ts` (§125 deterministic
  primitives), `tests/integration/part4-reasoning.test.ts` (§126-§128 full
  pipeline against the lab app: login → object endpoint → second identity →
  differential → hypothesis → verification), `tests/security/part4-reasoning-security.test.ts`
  (§115-§116 untrusted labeling, §132 permission boundaries, §113 limits).

---

## Part 5 — Knowledge subsystem operations (spec Part 5)

### Feature flag

`FEATURE_KNOWLEDGE_SEARCH=true` (default since Part 5) enables the
knowledge engine, its 15 API routes and the four `knowledge.*` worker
tools. Disabled deployments answer honest 501s and register no knowledge
tools.

### Seeding and synchronization

```bash
# Seed the curated catalog (OWASP WSTG/ASVS/API Top 10, PortSwigger,
# MDN, RFCs, CWE, CTF feeds) and activate the index version marker:
curl -XPOST /api/knowledge/sync -d '{"seed": true}'
# Sync a specific source's configured entry paths (bounded by
# KNOWLEDGE_SYNC_MAX_PAGES):
curl -XPOST /api/knowledge/sync -d '{"source_id": "KSR_..."}'
```

Sources carry `entry_paths` in their crawl policy — the platform is
curated and bounded, never an open crawler. Ingestion is idempotent:
identical content re-ingests to zero changes; changed content creates a
new version (§25); identical content at a new URL links to the canonical
document (§67).

### Embedding configuration

`KNOWLEDGE_EMBEDDING_PROVIDER` selects the semantic path:

* `hash` (default): fully deterministic, offline, no external calls —
  real local semantic-ish retrieval for development and tests.
* `google`: external REST embeddings (requires `GOOGLE_API_KEY`;
  degrades to keyword-only when absent — §116 honesty).
* `none`: keyword-only retrieval.

`KNOWLEDGE_EMBEDDING_MODEL` / `KNOWLEDGE_EMBEDDING_DIMENSION` configure
the provider. Model identifiers are never hard-coded (§107). Changing
the model activates a NEW index version row (§95) — cached packets never
cross index generations, and embeddings are reindexed per model.

### Live research

No web search provider is configured by default: `knowledge.search_web`
returns honest empty results with a note, and CURATED_WEB research
answers from the local index (§104). Operators inject a search provider
through the engine composition (tests use a deterministic fake).

The knowledge fetcher applies its OWN network policy (§26): SSRF defence
via DNS resolution before connection, loopback/private/link-local denial
(`KNOWLEDGE_ALLOW_LOOPBACK=true` for lab setups), per-source rate limits
(`KNOWLEDGE_RATE_PER_SOURCE_PER_MINUTE`), daily budget
(`KNOWLEDGE_DAILY_FETCH_BUDGET`), bounded reads
(`KNOWLEDGE_FETCH_MAX_PAGE_BYTES`) with explicit truncation flags and
redirect limits.

### Retrieval quality (§96-§98)

`GET /api/knowledge/status` reports corpus counts plus agent-utility
metrics (cache hit rate, avg results/tokens per query, zero-result
queries). The integration suite runs the §127 query set (authorization,
JWT, WebSocket, GraphQL, business logic, legacy API) as a retrieval
benchmark with Recall@K / MRR assertions; `computeMetrics()` in
`@aegis/knowledge` exposes Recall@K, Precision@K, MRR, NDCG, duplicate
rate and token statistics for custom evaluation sets.

### Tuning knobs

Retrieval weights (`KNOWLEDGE_*_WEIGHT`: semantic, keyword, trust,
freshness, context, specificity, duplicate penalty), chunk sizes
(`KNOWLEDGE_CHUNK_MIN/MAX_TOKENS`), packet budgets
(`KNOWLEDGE_MAX_PACKET_TOKENS`, `KNOWLEDGE_WORKER_PACKET_TOKENS`), cache
TTL (`KNOWLEDGE_CACHE_TTL_MS`), research budgets
(`KNOWLEDGE_RESEARCH_MAX_*`) and fetch limits
(`KNOWLEDGE_FETCH_*`) are documented in `.env.example`.

### Tests

```bash
npx vitest run --config vitest.unit.config.ts tests/unit/part5-knowledge.test.ts        # 41 unit
npx vitest run --config vitest.integration.config.ts tests/integration/part5-knowledge.test.ts  # 28 integration
npx vitest run --config vitest.security.config.ts tests/security/part5-knowledge-security.test.ts  # 20 security
```

# Part 6 — Autonomous engine operations

## Feature flag

`FEATURE_AUTONOMOUS_ENGINE` (default `true`). Requires
`FEATURE_SECURITY_REASONING` (the loop is built on the Part 4 candidate and
verification machinery). When off, all `/autonomous/*` routes return honest
`501 AUTONOMOUS_ENGINE_DISABLED`.

## Operating the engine

1. Create an engagement (PENTEST or CTF), scope, targets; start it.
2. CTF only: `POST /ctf/context` with the challenge text (title,
   description, hints, flag_format) — the engine extracts clues and
   interprets them deterministically (§29).
3. `POST /autonomous/start` — the engine persists its state, recovers
   incomplete tasks (§54), launches the agent run, compiles the §9 recon
   plan, and enters RECON.
4. Watch the dashboard (Autonomous tab): phase, branches, experimental
   registry, approvals, live timeline (auto-refresh every 3s while running).
5. Control: pause / resume / cancel / replan; approve or reject high-risk
   tasks; prioritize hypotheses.

## Tunables (`AUTONOMOUS_*`)

| Variable | Default | Purpose |
|---|---|---|
| `AUTONOMOUS_MAX_REPLANS` | 6 | Replan budget before a §50 stop |
| `AUTONOMOUS_MAINTENANCE_INTERVAL_MS` | 2500 | Fallback tick cadence (§8) |
| `AUTONOMOUS_RECON_MAX_TASKS` | 12 | Bounded §9 recon plan size |
| `AUTONOMOUS_RECON_MAX_PATHS_PER_TARGET` | 8 | §11 known-path bound |
| `AUTONOMOUS_CANDIDATE_BATCH` | 6 | §38 incremental candidate batch |
| `AUTONOMOUS_BRANCH_LIMIT` | 8 | Active branch budget (§65) |
| `AUTONOMOUS_HYPOTHESIS_LIMIT` | 12 | Hypotheses per consumption cycle |
| `AUTONOMOUS_TASK_LEASE_MS` | 120000 | Task lease duration (§55) |
| `AUTONOMOUS_LEASE_SWEEP_INTERVAL_MS` | 15000 | Lease sweep cadence |
| `AUTONOMOUS_STOP_MIN_TESTS` | 3 | Diminishing-returns window (§50) |
| `AUTONOMOUS_STOP_MAX_CONSECUTIVE_FAILURES` | 4 | Repeated-failure stop |
| `AUTONOMOUS_FLAG_PATTERNS` | `flag\{[A-Za-z0-9_-]{4,128}\};...` | Semicolon-separated flag regexes (§31) |
| `AUTONOMOUS_BUDGET_RECON_SHARE` / `_TESTING_SHARE` | 0.4 / 0.45 | §78 phase allocation |
| `AUTONOMOUS_TIMELINE_LIMIT` | 200 | Timeline response bound |
| `AUTONOMOUS_MAX_KNOWLEDGE_QUERY_REPEATS` | 2 | §40 knowledge anti-loop |

## Benchmarks

`tests/integration/part6-benchmark.test.ts` runs the offline benchmark set
(lab IDOR pentest + four CTF challenges) and persists metrics
(`benchmark_runs`): time to first/verified finding, false-positive rate,
duplicate-test rate, coverage, requests/tokens per finding, CTF solve rate.
`GET /api/benchmarks` lists definitions; `GET /api/benchmarks/:name/runs`
shows history.
