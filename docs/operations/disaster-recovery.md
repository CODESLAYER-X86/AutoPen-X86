# Disaster Recovery Runbook (Part 8 §63)

## Objectives

RPO 24h / RTO 30min (exercised continuously by `tests/security/part8-backup.test.ts`).

## Scenarios

| Loss | Recovery |
| --- | --- |
| Database host | restore latest verified backup (backup-restore.md), drain the outbox, resume engines from `autonomous_engine_states` |
| Object storage | evidence blobs are re-derivable; metadata + sha256 live in PostgreSQL; affected engagements re-run bounded recon |
| Worker fleet | leases expire per policy (worker-recovery.md); no state lives in workers |
| Queue | the durable record is the DB + outbox; memory queues rebuild from persistence |
| Orchestrator process | event-driven loop state is persisted; restart resumes phases exactly |
| Full region | rebuild from container image + latest verified backup + secret manager; run the §111 production readiness test before opening traffic |

## Verification after recovery

1. `npm run restore data/backups/<latest>.json` — verified.
2. `POST /api/audit-chain/verify` — tamper-evidence intact.
3. `/api/ready` — all dependencies healthy.
4. Emergency stop CLEAR, no open breakers on `/api/metrics`.
5. One canary engagement runs to the ANALYSIS phase with scope enforcement observed.

## Principles

- The model never owns state, scope, credentials or the network (§122).
- Security controls fail closed: if a control is down, target-bound actions stop.
- Human intervention always remains possible (approvals, breaker resets, emergency release).
