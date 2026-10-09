# Backup & Restore Runbook (Part 8 §62-§63)

## RPO / RTO

- **RPO** — 24h (daily logical backup; increase frequency with `npm run backup` in cron if needed).
- **RTO** — 30 minutes (restore = migrate scratch + load + verify; the verified path is exercised by `tests/security/part8-backup.test.ts` on every CI run).

## Backup

```
npm run backup            # data/backups/<timestamp>-<label>.json + backup_records row
```
The artifact is a deterministic logical dump (table list, row counts, per-table
sha256, INSERT statements). Production deployments may substitute `pg_dump` —
the verification contract (sha256 + restore into a scratch database + row-hash
equality) stays identical.

## Restore

```
npm run restore data/backups/<file>.json
```
1. Recreates `aegis_restore_check` from scratch (drop + create).
2. Applies versioned migrations, truncates seeded tables, loads rows.
3. Verifies every table's row count AND content hash.
4. Marks the source `backup_records.restore_verified_at`.

A backup that has never been restored is not a verified backup (§62): the
restore path runs in the automated test suite.

## Recovery scenarios (§63)

| Loss | Action |
| --- | --- |
| Database | restore latest verified backup + replay outbox (`hardening.outbox.drain()`) |
| Object storage | artifacts are re-derivable from metadata + sha256; re-run affected engagements |
| Queue | tasks are DB-leased (Part 6 §55); restart workers, leases recover |
| Orchestrator | state is persisted; the engine resumes phases from `autonomous_engine_states` |
| Model provider | provider-failure policy pauses replanning; see model-provider-outage.md |
