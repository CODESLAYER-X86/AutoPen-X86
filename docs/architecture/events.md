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

---

# Part 4 — reasoning events

Derived-state events published by the reasoning processor (all carry
deterministic `dedup_key`s; reprocessing is idempotent, §111):

ENDPOINT_DISCOVERED, ENDPOINT_CANONICALIZED, AUTHORIZATION_MATRIX_UPDATED,
SECURITY_SIGNAL_CREATED, OBJECT_CANDIDATE_UPSERTED, WORKFLOW_RECONSTRUCTED,
WORKFLOW_TRANSITION_RECORDED, AUTH_BOUNDARY (as WORKFLOW_TRANSITION_RECORDED
with `auth_boundary: true`), DIFFERENTIAL_COMPARISON_RECORDED,
VERIFICATION_CREATED, VERIFICATION_COMPLETED, REASONING_INGEST_COMPLETED.

Consumption: the processor itself subscribes to Part 3 events
(HTTP_REQUEST_RECORDED, DOM_SNAPSHOT_CAPTURED, SESSION_EXPIRATION_DETECTED,
auth-workflow events) per §109; raw events remain durable even when an
extractor fails (§110, §112).

---

## Part 5 — Knowledge event vocabulary (spec Part 5 §86, §119)

| Event | Meaning |
|---|---|
| `KNOWLEDGE_QUERY` | A structured knowledge query was issued (with query id, categories) |
| `KNOWLEDGE_RESULT` | Retrieval produced scored candidates |
| `WEB_RESEARCH_STARTED` | A bounded research task started (question, mode) |
| `WEB_SOURCE_SELECTED` | A candidate source was selected for fetching (URL, domain, trust) |
| `WEB_DOCUMENT_FETCHED` | A knowledge document was fetched (bounded bytes, truncation flag) |
| `KNOWLEDGE_PACKET_CREATED` | A compact packet was assembled (results, tokens, truncated) |
| `KNOWLEDGE_SOURCE_SYNCED` | A curated source was synchronized |
| `KNOWLEDGE_DOCUMENT_INDEXED` | A document completed ingestion (chunks, status) |
| `KNOWLEDGE_INGESTION_FAILED` | A ingestion stage failed (stage, error) |
| `RESEARCH_COMPLETED` | A research task completed or failed |

Knowledge events use the `global` engagement id when not engagement-bound.
Retrieval auditing additionally persists `knowledge_queries` /
`knowledge_results` rows with the full scoring dimensions (§85, §97-§98).

# Part 6 — Autonomous engine events (spec Part 6 §8, §6, §25-26, §31, §41-42, §48-50, §55, §87)

| Event | Meaning |
|---|---|
| `AUTONOMOUS_ENGINE_STARTED` | Engine started for an engagement (mode, reason) |
| `AUTONOMOUS_PHASE_CHANGED` | Persisted phase transition (from, to, terminal) |
| `AUTONOMOUS_ENGINE_PAUSED` / `_RESUMED` / `_STOPPED` | Control actions (§48, §73) |
| `AUTONOMOUS_RECOVERY_COMPLETED` | Crash recovery recovered N tasks (§54) |
| `RECON_PIPELINE_STARTED` / `RECON_TASK_PLANNED` / `RECON_PIPELINE_COMPLETED` | Deterministic recon pipeline (§9) |
| `HYPOTHESIS_CANDIDATES_CONSUMED` | Candidate groups → hypotheses + branches (§14-§16) |
| `TEST_CANDIDATES_COMPILED` | Planned tests compiled into worker tasks (§38) |
| `REASONING_BRANCH_CREATED` / `_UPDATED` / `_PRUNED` | Branch lifecycle (§65-§66) |
| `DIFFERENTIAL_AUTO_REQUESTED` | Auto differential after a test task (§19) |
| `VERIFICATION_BRIDGE_APPLIED` | Verdict applied to hypothesis/finding (§26) |
| `FINDING_CONFIDENCE_COMPUTED` | §28 confidence model attached (confidence, level) |
| `STOP_CONDITION_MET` | A §50 stop condition matched (reason, detail) |
| `BUDGET_THRESHOLD_EXCEEDED` | Budget above the 80% threshold (§42) |
| `TASK_LEASE_EXPIRED` | Lease sweep applied recovery policies (§55) |
| `APPROVAL_REQUESTED` / `APPROVAL_DECIDED` | Human approval flow (§48-§49) |
| `CTF_CONTEXT_CREATED` / `CTF_CLUE_ANALYZED` | Challenge ingestion + clue interpretation (§29) |
| `FLAG_CONDITION_HYPOTHESIZED` / `FLAG_DETECTED` / `CHALLENGE_SOLVED` | §31 success-condition evidence chain |
| `COVERAGE_UPDATED` | Coverage model recomputed (§51) |
| `REPLAN_REQUESTED` | Replanning trigger recorded (§75) |
| `BENCHMARK_RUN_COMPLETED` | Evaluation run finished with metrics (§79) |

The correlation chain decision → task → worker → tool call → observation →
hypothesis → evidence → verification → finding stays connected through
event payloads + trace ids (§85).

## Part 7 — Verification, Reporting & Evaluation

| Event | Meaning |
| --- | --- |
| `FINDING_CANDIDATE_CREATED` | Candidate finding created from structured observation (§6) |
| `FINDING_TRANSITION_RECORDED` | Guarded lifecycle transition (§4-§5, engine or human) |
| `FINDING_DEDUPLICATED` | Same-root-cause findings merged (§19-§20) |
| `VERIFICATION_PLAN_CREATED` / `VERIFICATION_PLAN_EXECUTED` | Plan with §7 sufficiency gate; execution result (§8, §14) |
| `REPRODUCTION_ATTEMPTED` | Real replay through the controlled HTTP port (§12) |
| `CONTROL_TEST_EXECUTED` | Control comparison over the authorization matrix (§9) |
| `ALTERNATIVE_EXPLANATION_TESTED` | Alternatives searched for refutations (§10) |
| `CONFIDENCE_RECALCULATED` | Deterministic confidence dimensions (§15) |
| `SEVERITY_COMPUTED` | CVSS 3.1 calculator output (§17-§18) |
| `HUMAN_REVIEW_RECORDED` | Audited human decision, agent conclusion preserved (§67) |
| `RETEST_REQUESTED` / `RETEST_COMPLETED` | Security-property re-verification (§37-§38) |
| `REPORT_GENERATION_STARTED` / `REPORT_VALIDATED` / `REPORT_REJECTED` / `REPORT_EXPORTED` | The §31 pipeline with the §65 validation gate |
| `REPORT_CLAIM_FLAGGED` | Claim scope exceeded evidence and was rewritten (§33) |
| `EVALUATION_RUN_STARTED` / `EVALUATION_SCENARIO_COMPLETED` / `EVALUATION_RUN_COMPLETED` | Evaluation lifecycle (§42, §59) |
| `EVALUATION_EVENT_RECORDED` | Safety observations (scope refusals, injection containment) (§76-§82) |
| `REGRESSION_CHECK_COMPLETED` / `RELEASE_GATE_DECIDED` | §88-§89 release gates |
| `GOLDEN_RUN_SAVED` | Behavioral golden reference stored (§90) |

The verification chain finding → plan → reproduction/controls →
alternatives → confidence → verdict → report → export stays connected
through event payloads; report artifacts are hash-manifested (§66).
