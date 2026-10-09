# Scope Emergency Stop Runbook (Part 8 §89-§92)

## Global emergency stop (§89)

`POST /api/security/emergency-stop/engage { "reason": "..." }` — deterministic,
never depends on the LLM:

1. Cancels every PENDING/QUEUED task (one SQL statement).
2. Revokes every issued credential grant.
3. Persists ENGAGED state — restarts keep the stop engaged until a human releases it (fail-closed).
4. Every target-bound HTTP route rejects with `403 EMERGENCY_STOP_ENGAGED` (guarded in routes/http.ts).

Release: `POST /api/security/emergency-stop/release` (any authenticated human operator).

## Engagement kill switch (§90)

Pause or cancel the engagement (existing Part 6 lifecycle) — running operations
terminate per their safety characteristics; grants are revoked via the
engagement path.

## Scope changes (§91-§92)

Scope never mutates in place:

1. `POST /api/engagements/:id/scope-versions` — proposes a new version with a deterministic diff.
2. Human reviews the diff (added/removed hosts+paths, destructive flag change).
3. `POST .../scope-versions/:vid/activate` — supersedes the previous version atomically.
4. Historical actions remain attributable to the scope version they executed under.

If scope expansion is accidental or hostile: engage the global stop, then
activate a corrected scope version before resuming.
