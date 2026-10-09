# Deployment Runbook (Part 8 §116-§117)

## Architecture separation

- **Control plane** — API, orchestrator, policy, scheduler: `apps/api` (the container image).
- **Data plane** — PostgreSQL (external service, `docker-compose.yml`), object storage under `STORAGE_LOCAL_PATH`.
- **Worker plane** — HTTP/browser/analysis workers: separate deployables with stricter egress policies; they never receive the platform secret store wholesale (Part 8 §14-§15 grants).

## Steps

1. **Pre-flight gates (§111)** — all green before shipping:
   ```
   npm run typecheck && npm run lint && npm run build
   npm run test
   npm run deps:audit            # fails on high/critical advisories
   ```
2. **Migrations (§64)** — backup, test, apply, verify:
   ```
   npm run backup                # logical dump + backup_records row
   npx tsx scripts/db/migrate.ts # versioned migrations only
   npm run restore data/backups/<latest>.json   # verified restore into scratch DB
   ```
3. **Container** — build with the hardened Dockerfile (non-root `aegis` user, dropped capabilities, no docker socket). The app connects as the `aegis_app` PostgreSQL role which is subject to RLS (migration 076) — set `aegis.tenant_user_id` per connection.
4. **Secrets (§12-§13)** — `SECRET_STORE_MASTER_KEY`, `INTERNAL_SERVICE_TOKEN_SECRET` and `GOOGLE_API_KEY` come from the deployment secret manager, never from committed files. Rotate via `docs/operations/credential-rotation.md`.
5. **Health verification** — `/api/health` (liveness) and `/api/ready` (readiness incl. PostgreSQL probe) must both answer 200; `/api/metrics` must show `emergency_stop_engaged: false` and `pending_outbox_events: 0`.

## Known pre-production advisories (honest boundary)

`npm run deps:audit` currently reports HIGH advisories for `fastify<=5.12.4` /
`find-my-way<=9.6.0` (routing layer). The gate is intentionally failing closed
until the Fastify 4 → 5 upgrade is regression-tested through the Part 7
evaluation suite — the upgrade itself is a software change (§100-§101) and must
not skip the benchmark + regression gates.

## Rollback

See `rollback.md`. Every deployment is reversible: previous image tag, previous
model/prompt configuration (Part 7 model-config snapshots) and migration
compatibility are all retained.
