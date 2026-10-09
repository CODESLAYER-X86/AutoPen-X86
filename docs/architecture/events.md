# Event System

## Design

Two complementary records:

* **events** (`events` table) — system telemetry for everything significant
  that happens, with correlation columns (engagement, task, trace, actor).
  The UI "Activity" tab is this stream.
* **audit_log** — security-sensitive human actions (who changed the scope,
  who started the engagement, who verified evidence).

`PersistingEventBus` (packages/events) persists FIRST (losing an event is
worse than failing the operation), then fans out to in-process subscribers
with per-subscriber error isolation.

## Vocabulary (spec §14 — all reserved now, emitted incrementally)

Engagement: `ENGAGEMENT_CREATED`, `ENGAGEMENT_UPDATED`, `ENGAGEMENT_READY`,
`ENGAGEMENT_STARTED`, `ENGAGEMENT_PAUSED`, `ENGAGEMENT_RESUMED`,
`ENGAGEMENT_COMPLETED`, `ENGAGEMENT_FAILED`, `ENGAGEMENT_CANCELLED`

Surface: `TARGET_ADDED`, `TARGET_REJECTED`, `SCOPE_UPDATED`,
`IDENTITY_CREATED`

Observation/reasoning (Parts 2+): `OBSERVATION_CREATED`,
`HYPOTHESIS_CREATED`, `HYPOTHESIS_UPDATED`, `TASK_CREATED`, `TASK_STARTED`,
`TASK_COMPLETED`, `TASK_FAILED`, `AGENT_DECISION`, `AGENT_ERROR`

Workers (Parts 3–4): `HTTP_REQUEST_SENT`, `HTTP_RESPONSE_RECEIVED`,
`BROWSER_NAVIGATION`, `BROWSER_ACTION`, `BROWSER_REQUEST`, `BROWSER_RESPONSE`

Findings/evidence: `EVIDENCE_CREATED`, `FINDING_CREATED`, `FINDING_VERIFIED`,
`TOOL_INVOKED`, `TOOL_COMPLETED`

## Correlation IDs

Every event row carries: prefixed event id (`EVT_…`), optional engagement
id, task id, trace id (`TRC_…`, minted per logical operation), and actor id.
HTTP requests additionally carry `REQ_…` request ids which appear in logs and
error envelopes, so a failure can be traced end-to-end:

```
request REQ_… -> log http.request -> tool TOOL_… (later parts)
             -> event TARGET_REJECTED (trace TRC_…) -> audit TARGET_REJECTED
```

## Event shape

```jsonc
{
  "id": "EVT_7QK2M…",
  "type": "ENGAGEMENT_STARTED",
  "engagement_id": "ENG_…",
  "task_id": null,
  "trace_id": "TRC_…",
  "actor_id": "USR_…",
  "payload": { "from": "READY", "to": "RUNNING" },
  "occurred_at": "2026-10-09T12:00:00.000Z"
}
```

Payloads are platform-generated structured data. Raw target-controlled
content belongs in evidence, not in events (spec §1.4).

---

# Event Vocabulary — Part 2 additions (spec Part 2 §59)

New correlation carriers: `RUN_` ids appear in payloads; task ids and trace
ids continue to correlate every agent operation.

| Event | When |
|---|---|
| `AGENT_RUN_CREATED / STARTED / PAUSED / RESUMED / WAITING / COMPLETED / FAILED / CANCELLED` | run lifecycle (§3) |
| `AGENT_CYCLE_COMPLETED` | every decision cycle, with its outcome (§31) |
| `LEADER_DECISION_RECORDED / REJECTED` | decision validation results (§10) |
| `TASK_QUEUED / DISPATCHED / RETRY / CANCELLED / RECOVERY_PENDING / BLOCKED` | scheduler mechanics |
| `WORKER_STARTED / COMPLETED` | worker execution (§2 TaskAttempt) |
| `HYPOTHESIS_CONFIRMED / DISPROVED / ABANDONED` | hypothesis resolution (§22) |
| `TEST_RECORDED / TEST_DUPLICATE` | test registry + dedup (§28-§29) |
| `DEAD_END_RECORDED` | dead-end memory (§27) |
| `STRATEGY_CHANGED` | strategy memory version bump (§49) |
| `VERIFICATION_REQUESTED` | leader or worker requests verification (§56) |
| `FINDING_REJECTED` | promotion ladder rejection (§55) |
| `QUOTA_DELAY / QUOTA_EXHAUSTED` | quota pressure (§37-§40) |
| `OSCILLATION_DETECTED` | strategy oscillation without new evidence (§52) |
| `LOOP_PROTECTION_TRIGGERED` | anti-loop actions fired (§51) |
| `HUMAN_OVERRIDE` | operator intervention, always audited (§46) |

Events may carry a `dedup_key` (unique index): recovery replays never
duplicate audit records (§65).

## Part 3 — interaction events

`HTTP_REQUEST_RECORDED`, `HTTP_RESPONSE_RECORDED`,
`HTTP_MUTATION_APPLIED`, `HTTP_REPLAY_EXECUTED`, `HAR_IMPORTED`,
`BROWSER_SESSION_STARTED`, `BROWSER_SESSION_CLOSED`,
`BROWSER_CONTEXT_CREATED`, `BROWSER_CONTEXT_CLOSED`,
`BROWSER_EVENT_RECORDED`, `DOM_SNAPSHOT_CAPTURED`,
`DOM_CHANGE_DETECTED`, `DOWNLOAD_CAPTURED`,
`WEBSOCKET_CONNECTION_OBSERVED`, `WEBSOCKET_MESSAGE_OBSERVED`,
`SESSION_EXPIRATION_DETECTED`, `AUTH_WORKFLOW_RECORDED`,
`TOOL_EXECUTION_RECORDED`, `RATE_LIMIT_ENFORCED`.

Each browser action boundary flushes the structured event buffer; network
captures additionally emit the HTTP record events through the traffic
recorder. Every event payload is bounded and redacted upstream (§66).
