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
