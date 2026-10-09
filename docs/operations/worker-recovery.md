# Worker Recovery Runbook (Part 8 §40-§42, §54-§55, §58)

## Lease-based recovery (§40-§42)

Tasks are claimed with DB-level leases (conditional UPDATE + lease expiry).
If a worker crashes:

1. The lease expires (`AUTONOMOUS_TASK_LEASE_MS`, default 120s).
2. The Part 6 recovery policy decides per retry fingerprint: SAFE_RETRY replays
   read-only work; MARK_FAILED records the failure without replaying state-
   changing actions (never blindly replay mutations).
3. Duplicate events are tolerated: consumers key on idempotency keys; the
   outbox delivers at-least-once with bounded retries, then ABANDONS visibly.

## Browser crash recovery (§54)

Browser workers run identity-isolated contexts (Part 3). On a Playwright
crash: the failure is captured, task state persists, the isolated context is
restarted fresh (storage is NOT replayed), and the task re-runs through the
same policy path. Sessions signal `NEEDS_IDENTITY` on expiry (§55) — the
agent requests re-authentication rather than retrying blindly.

## Backpressure (§58)

Bounded batches everywhere: outbox drains cap at 50 per pass, retention sweeps
at 500 per table, observation processing is queue-bounded. If workers outpace
analysis, pending counts rise on `/api/metrics` (`pending_outbox_events`) —
scale the analysis plane, never remove the bounds.
