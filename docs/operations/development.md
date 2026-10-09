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
