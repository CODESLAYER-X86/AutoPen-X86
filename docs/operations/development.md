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
