# Rollback Runbook (Part 8 §103-§104)

## What is kept for reversibility

- **Application** — previous container image tag (registry retains N tags).
- **Model configuration** — `evaluation_model_configs` snapshots (Part 7 §83): previous strategic/tactical/embedding config.
- **Prompts** — `model_calls.prompt_version` records every generation; prompt bundles are versioned in-repo.
- **Database** — versioned migrations are backward-compatible within one minor version; pre-migration backups exist for point-in-time restore.

## Procedure

1. **Detect** — regression gate failure (Part 7 §88-§91), spike in scope denials / tool errors / false positives on `/api/metrics`, or open HIGH/CRITICAL incidents.
2. **Pause rollout** — engage the emergency stop if target-bound behaviour is unsafe (§89), otherwise stop scheduling by pausing engagements.
3. **Roll back** — deploy the previous image tag; revert model config to the last snapshot; migrations within the compatibility window need no action.
4. **Verify** — `/api/ready` green, `npm run restore data/backups/<pre-deploy>.json` verified, benchmark comparison shows no regression.
5. **Document** — record the incident and root cause; every platform bug becomes a regression test (§113).

## Model-specific rollback (§101)

Never auto-switch models in production. New model versions go through: offline
benchmark → security benchmark → regression comparison → cost comparison →
human review → staged rollout (10% → 25% → 50% → 100%).
