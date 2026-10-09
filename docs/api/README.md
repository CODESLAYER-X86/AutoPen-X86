# API Reference (Part 1 + Part 2)

Base URL: `http://127.0.0.1:4000` (dev). All bodies and responses are JSON.
Errors use one envelope:

```json
{
  "error": {
    "code": "TARGET_OUT_OF_SCOPE",
    "message": "Target rejected by scope validation: …",
    "category": "SCOPE",
    "details": { "code": "HOST_NOT_ALLOWED" },
    "request_id": "REQ_…"
  }
}
```

`details` is only present for 4xx client errors. 5xx bodies never leak
internals.

## Public

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/api/meta` | — | platform status: model roles, feature flags, tool counts, `autonomous_run_loop: false` |
| POST | `/api/auth/register` | `{email, name, password≥10}` | 201 `User` |
| POST | `/api/auth/login` | `{email, password}` | 200 `{token, expires_at, user}` |

## Authenticated (Bearer token)

| Method | Path | Body / notes |
|---|---|---|
| GET | `/api/auth/me` | current user |
| POST | `/api/auth/logout` | 204, revokes the session |
| GET | `/api/tools` | registry descriptors with `implemented` flags |
| POST | `/api/projects` | `{name, description?}` |
| GET | `/api/projects` | page of owned projects |
| GET | `/api/projects/:id` | 404 when not owned |
| GET | `/api/projects/:id/engagements` | list |
| POST | `/api/engagements` | `{project_id, name, mode: PENTEST\|CTF, description?}` |
| GET | `/api/engagements` | engagements across own projects |
| GET | `/api/engagements/:id` | `{engagement, readiness}` |
| PATCH | `/api/engagements/:id` | `{name?, description?, status?}` — status routes through the state machine |
| POST | `/api/engagements/:id/scope` | scope rules (upsert; rejected while RUNNING) |
| GET | `/api/engagements/:id/scope` | `{scope: null | Scope}` |
| POST | `/api/engagements/:id/targets` | `{type, value, label?}` — deterministic scope check BEFORE insert; violations 422 + audit |
| GET | `/api/engagements/:id/targets` | list |
| POST | `/api/engagements/:id/identities` | `{name, role?, type: ANONYMOUS\|USER\|ADMIN\|SERVICE, metadata?}` |
| GET | `/api/engagements/:id/identities` | list |
| POST | `/api/engagements/:id/start` | DRAFT auto-promotes to READY when preconditions hold |
| POST | `/api/engagements/:id/pause` / `resume` / `cancel` | lifecycle transitions (pause/cancel propagate to the active agent run) |
| GET | `/api/engagements/:id/events?limit=` | event stream (Activity tab) |
| GET | `/api/engagements/:id/audit?limit=` | audit trail |
| GET | `/api/engagements/:id/evidence` | evidence metadata (never raw content) |
| GET | `/api/engagements/:id/evidence/:evidenceId/verify` | hash re-verification |

## Authenticated — Agent Operating System (Part 2, spec §45-§46, §58)

| Method | Path | Body / notes |
|---|---|---|
| POST | `/api/engagements/:id/runs` | `{reason?}` — 201 `AgentRun`; requires engagement RUNNING; one active run per engagement (400 `AGENT_RUN_ALREADY_ACTIVE`) |
| GET | `/api/engagements/:id/runs?limit=` | run history with metrics |
| POST | `/api/engagements/:id/runs/:runId/pause` | operator pause — checked every loop tick |
| POST | `/api/engagements/:id/runs/:runId/resume` | resume; re-attaches the engine after a restart (§63) |
| POST | `/api/engagements/:id/runs/:runId/cancel` | immediate stop of autonomous activity |
| GET | `/api/engagements/:id/tasks?status=&limit=` | task list with priorities, attempts, failure codes |
| POST | `/api/engagements/:id/tasks/:taskId/cancel` | human task cancellation (audited) |
| GET | `/api/engagements/:id/hypotheses?limit=` | hypothesis registry (competing, branched) |
| GET | `/api/engagements/:id/strategies` | versioned strategy memory (§49) |
| GET | `/api/engagements/:id/dead-ends` | dead-end memory (§27) |
| GET | `/api/engagements/:id/observations?limit=` | structured worker observations |
| GET | `/api/engagements/:id/findings` | promotion-ladder outcomes (§55) |
| GET | `/api/engagements/:id/agent-metrics` | §58 observability aggregate |
| POST | `/api/engagements/:id/overrides` | human overrides (§46), all audited: `{kind: ADD_CTF_CLUE, clue}` \| `{kind: PRIORITIZE_HYPOTHESIS, hypothesis_id, priority}` \| `{kind: CANCEL_TASK, task_id, reason?}` \| `{kind: REQUEST_VERIFICATION, hypothesis_id, reason?}` \| `{kind: PAUSE_RUN, reason?}` |
| POST | `/api/engagements/:id/recovery` | crash recovery (§63-§64): finalize-from-output / re-queue / fail |

## Status codes of note

* 400 `BODY_INVALID` / `INVALID_ENGAGEMENT_TRANSITION` / `ENGAGEMENT_PRECONDITIONS_NOT_MET` / `ENGAGEMENT_NOT_RUNNING` / `AGENT_RUN_ALREADY_ACTIVE` / `HYPOTHESIS_NOT_FOUND` / `TASK_NOT_FOUND`
* 401 `UNAUTHENTICATED` / `INVALID_TOKEN`
* 404 `*_NOT_FOUND` (also cross-tenant)
* 413 `BODY_TOO_LARGE`
* 422 `TARGET_OUT_OF_SCOPE` / `SCOPE_NOT_CONFIGURED`
* 429 `RATE_LIMIT_EXCEEDED`
* 501 reserved for not-implemented subsystems

Contracts live in `packages/contracts` and are the single source of truth for
both frontend and backend (spec §28).

## Part 3 — interaction endpoints

All authenticated; engagement ownership enforced (404 on foreign resources).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/engagements/:id/http/requests` | paginated traffic list (§16) |
| GET | `/api/engagements/:id/http/requests/:requestId` | request + response pair |
| POST | `/api/engagements/:id/http/request` | send a request (gateway path) (§15) |
| POST | `/api/engagements/:id/http/replay` | replay a recorded request (§19) |
| POST | `/api/engagements/:id/http/mutate` | structured mutation + execute (§20-§22) |
| POST | `/api/engagements/:id/http/har-import` | import HAR traffic (untrusted, scope-filtered) (§80) |
| GET | `/api/engagements/:id/tool-executions` | tool execution audit log (§78) |
| POST | `/api/engagements/:id/browser/contexts` | open an identity context (§3-§4) |
| GET | `/api/engagements/:id/browser/contexts` | list contexts |
| POST | `/api/engagements/:id/browser/contexts/:cid/close` | deterministic cleanup (§75) |
| POST | `/api/engagements/:id/browser/actions` | structured browser action (§7-§8) |
| GET | `/api/engagements/:id/browser/events` | structured event stream (§11) |
| GET | `/api/engagements/:id/browser/snapshots` | DOM snapshot list (§32) |
| GET | `/api/engagements/:id/browser/cookies` | cookie descriptors (redacted, §23) |
| GET | `/api/engagements/:id/browser/storage` | storage entries (redacted, §24) |
| POST | `/api/engagements/:id/browser/contexts/:cid/capture-state` | capture cookies + storage |
| POST | `/api/engagements/:id/browser/contexts/:cid/promote-session` | record login workflow -> identity session (§28) |
| GET | `/api/engagements/:id/browser/downloads` | captured downloads (§37) |
| GET | `/api/engagements/:id/browser/websockets` | WS connections + messages (§36) |
| GET | `/api/engagements/:id/auth-workflows` | recorded auth workflows (§28) |

## Part 4 — security reasoning routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/engagements/:id/reasoning/status` | counts + recent processor failures (§113) |
| POST | `/api/engagements/:id/reasoning/ingest` | backfill ingestion over recorded traffic (§110) |
| GET | `/api/engagements/:id/reasoning/endpoints` | canonical attack surface (§7-§13) |
| GET | `/api/engagements/:id/reasoning/parameters` | parameter registry (§14-§15) |
| GET | `/api/engagements/:id/reasoning/signals` | signals (filter `?status=NEW`) (§42-§43) |
| GET | `/api/engagements/:id/reasoning/authorization-matrix` | identity × endpoint × object outcomes (§23) |
| GET | `/api/engagements/:id/reasoning/objects` | object candidates (§19) |
| GET | `/api/engagements/:id/reasoning/workflows` | reconstructed workflows (§34) |
| GET | `/api/engagements/:id/reasoning/workflows/:wid` | states + transitions detail |
| GET | `/api/engagements/:id/reasoning/data-flows` | source→sink flows (§37-§41) |
| GET | `/api/engagements/:id/reasoning/graph` | attack nodes + edges (§4-§5) |
| GET | `/api/engagements/:id/reasoning/hypotheses/candidates` | deterministic competing candidates (§44-§45) |
| POST | `/api/engagements/:id/reasoning/hypotheses/candidates/consume` | mark signals consumed |
| GET | `/api/engagements/:id/reasoning/test-candidates` | planned tests + preconditions (§118) |
| GET | `/api/engagements/:id/reasoning/differentials` | recorded comparisons (§25) |
| POST | `/api/engagements/:id/reasoning/differential` | compare two recorded requests |
| GET | `/api/engagements/:id/reasoning/verifications` | verification records (§72) |
| POST | `/api/engagements/:id/reasoning/verify` | evaluate a hypothesis skeptically |
| POST | `/api/engagements/:id/reasoning/query` | focused attack-surface query (§80) |
| GET | `/api/engagements/:id/reasoning/projection` | leader security projection (§120) |

When `FEATURE_SECURITY_REASONING=false` these routes answer **501**
(`SECURITY_REASONING_DISABLED`) — honest unavailability. Worker tools:
`reasoning.query`, `differential.compare`, `verification.evaluate`
(READ_ONLY, engagement-bound).

---

## Part 5 — Knowledge & Web Research (spec Part 5 §112)

All routes require a bearer token. Mutating routes are audited. When the
knowledge subsystem is disabled (`FEATURE_KNOWLEDGE_SEARCH=false`) the
routes answer **501 KNOWLEDGE_DISABLED** — honest unavailability.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/knowledge/search` | Hybrid retrieval → compact, token-bounded packet (§17/§61) |
| POST | `/api/knowledge/similar` | Similar-case retrieval from CTF case memory (§36) |
| POST | `/api/knowledge/research` | Bounded live research task (§30/§72) |
| GET | `/api/knowledge/research/:id` | Research task detail (sources, result, budgets) |
| POST | `/api/knowledge/fetch` | Bounded live fetch + ingestion (§26/§115) |
| POST | `/api/knowledge/ctf` | Ingest a CTF write-up with pattern extraction (§39/§42) |
| GET | `/api/knowledge/sources` | Source registry (optional `?enabled=true`) |
| GET | `/api/knowledge/techniques` | Structured security techniques (optional `?category=`) |
| GET | `/api/knowledge/documents/:id` | Document with provenance |
| GET | `/api/knowledge/documents/:id/versions` | Version history (§25) |
| GET | `/api/knowledge/documents/:id/references` | Extracted CVE/CWE/OWASP references |
| GET | `/api/knowledge/chunks/:id` | Chunk detail with heading path |
| GET | `/api/knowledge/queries` | Retrieval audit trail (§85) |
| GET | `/api/knowledge/status` | Corpus + agent-utility metrics (§97-§98) |
| POST | `/api/knowledge/sync` | ADMIN (audited): seed catalog + sync sources (§29) |

Engagement-scoped requests (`engagement_id` present) require engagement
ownership. Worker-facing equivalents are the `knowledge.search`,
`knowledge.similar_cases`, `knowledge.search_web` and `knowledge.fetch`
tools (§33-§36) — live web tools require the `knowledgeWeb` permission
(§84).
