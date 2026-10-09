# Model Provider Outage Runbook (Part 8 §39, §52, §99)

## Detection

- `/api/ready` — the readiness report flips to `waiting_for_resource: true` when dependencies degrade.
- Model circuit breaker (§99): invalid JSON, policy-violating decisions, extreme token usage or hallucinated tools trip `INVALID_MODEL_OUTPUT` / `MODEL_POLICY_BYPASS` breakers; the model configuration is disabled until a human resets it.
- Quota exhaustion surfaces through the Part 2 quota manager metrics.

## Response ladder (§39)

1. **timeout / rate limit** — the request-level retry with backoff handles it.
2. **quota exhaustion** — the quota manager pauses the loop; engagements wait, nothing fails.
3. **provider outage** — orchestrator enters WAITING_FOR_RESOURCE (readiness reflects it); scheduled work pauses, persisted state survives.
4. **pathological output** — the model circuit breaker disables that model configuration. Fallback or human intervention follows. Never auto-switch models across policy or budget boundaries.

## Recovery

1. Provider health returns (probe the readiness dependency).
2. Human resets the breaker: `POST /api/security/breakers/:id/reset`.
3. Resume paused engagements (Part 6 lifecycle).
4. A model version change afterwards goes through the §101 upgrade process — never a silent switch.
