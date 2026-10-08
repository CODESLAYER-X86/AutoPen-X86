# Data Model

All identifiers are application-generated prefixed IDs (`USR_`, `PRJ_`, `ENG_`,
`TGT_`, `SCP_`, `AST_`, `IDN_`, `SES_`, `EVT_`, `AUD_`, `EVD_`) — 128 bits of
base32 entropy from a CSPRNG, so correlation works across logs, events and the
database without coordination.

## Entity relationships

```
users 1--* projects 1--* engagements 1--1 scope
                                  |---* targets
                                  |---* assets (self-referencing parent_id)
                                  |---* identities 1--* sessions
                                  |---* events
                                  |---* audit_log
                                  |---* evidence (self-referencing parent_id)
users 1--* auth_sessions (platform login; token hash only)
```

## Tables (migrations in packages/database/migrations, hash-tracked)

| Table | Purpose | Security-relevant details |
|---|---|---|
| `users` | platform operators | scrypt password hashes, role CHECK, unique email |
| `projects` | grouping + ownership boundary | owner FK cascade |
| `engagements` | one authorized test/CTF run | mode/status CHECKs (state machine mirrored in DB) |
| `scope` | single row per engagement (UNIQUE) | allow/deny arrays, destructive flag |
| `targets` | scope-validated attack surface | UNIQUE(engagement, type, value); inserted only after deterministic scope check |
| `assets` | recon output, future attack-surface graph | self-FK parent_id |
| `identities` | Anonymous/User/Admin/Service roles | UNIQUE(engagement, name) |
| `sessions` | TARGET-side credentials | secret_reference only — plaintext never stored |
| `auth_sessions` | platform login | SHA-256 token hash, expiry, revocation |
| `events` | durable event log (spec §14) | correlation: engagement/task/trace/actor |
| `audit_log` | who did what (spec §30) | actor FK, action, resource, metadata |
| `evidence` | immutable, content-addressed | UNIQUE(engagement, sha256), parent_id for derivations |
| `platform_migrations` | migration ledger | sha256 of each applied .sql (drift detection) |

## State (engagement)

`DRAFT -> READY -> RUNNING <-> PAUSED -> COMPLETED | FAILED | CANCELLED`

* `DRAFT -> READY` happens automatically when a scope exists AND at least one
  in-scope target has been added.
* `RUNNING` sets `started_at` (first time only); terminal states set
  `completed_at`.
* All transitions go through `EngagementsRepository.updateStatus` — one write
  path, no direct status writes anywhere else.

## Evidence integrity (spec §22)

* Content is hashed (SHA-256) BEFORE storage; the object store keys objects
  by that hash (sharded directories), refusing key/content divergence.
* DB rows store `content_reference` (the hash) — never raw bytes.
* Idempotent per engagement: identical content maps to one record.
* `verify()` re-reads and re-hashes; mismatches are reported, not repaired.
* Derived evidence must reference an existing parent (`parent_id` +
  `metadata.derived_from`).

## Objects and secrets

* Large artifacts (screenshots, HAR, bodies) live in the local object store
  (`data/artifacts`) via `ObjectStore`; a future S3-style backend implements
  the same interface.
* Secret material lives in `data/secrets/secrets.json`, AES-256-GCM encrypted
  with a master key from `SECRET_STORE_MASTER_KEY` (or a generated dev key
  file, gitignored). The DB and logs only ever see `SEC_…` references.

## What is NOT modelled yet (deliberately)

Tasks, observations, hypotheses, tests and findings belong to Parts 2+; the
event vocabulary already reserves their event types so the schema can grow
without breaking the audit story.

---

# Data Model — Part 2 additions (Agent Operating System)

New prefixed IDs: `RUN_` (agent runs), `DCS_` (decisions), `TSK_` (tasks),
`ATT_` (task attempts / worker runs), `OBS_` (observations), `HYP_`
(hypotheses), `TST_` (tests), `DDE_` (dead ends), `STG_` (strategies),
`FND_` (findings), `MSG_` (agent messages), `MCL_` (model calls), `BGT_`
(budgets).

## Entity relationships (Part 2)

```
engagements 1--* agent_runs 1--* agent_decisions (cycle-unique)
                   |---* strategies (versioned per engagement)
                   |---* model_calls (token usage per purpose)
engagements 1--* tasks 1--* task_attempts (worker runs, attempt-unique)
                   |---* observations
engagements 1--* hypotheses (self-FK parent_hypothesis_id: branches)
                   |---* hypothesis_links (-> OBS_/TST_/EVD_ refs)
                   |---* findings (promotion, idempotent per hypothesis)
engagements 1--* tests (UNIQUE(engagement, fingerprint): dedup)
engagements 1--* dead_ends
engagements 1--1 engagement_budgets  (limits, §66)
engagements 1--1 engagement_usage    (atomic counters, §66)
agent_messages: full prompt/response audit (untrusted_bytes counted)
```

## New tables (migrations 013–027)

| Table | Purpose | Security-relevant details |
|---|---|---|
| `agent_runs` | one autonomous session | status CHECK (state machine); metrics JSON |
| `agent_decisions` | every leader decision | UNIQUE(run, cycle); input_state_hash; validation_status |
| `hypotheses` | hypothesis registry | status/transition CHECKs; confidence in [0,1]; branch parent FK |
| `hypothesis_links` | evidence graph | UNIQUE(hyp, ref_type, ref_id) |
| `observations` | worker-derived facts | confidence in [0,1]; evidence_ids JSON |
| `tasks` | investigation tasks | status CHECK; worker CHECK; UNIQUE(engagement, idempotency_key) |
| `task_attempts` | worker runs | UNIQUE(task, attempt); tokens/tools recorded |
| `tests` | test registry | UNIQUE(engagement, fingerprint) — deterministic dedup |
| `dead_ends` | exhausted branches | tests JSON list + reason |
| `strategies` | strategy memory | UNIQUE(engagement, version) |
| `findings` | promotion ladder outcome | status CHECK (PROPOSED/CONFIRMED/REJECTED) |
| `agent_messages` | prompt audit trail | channel/direction/role CHECKs; untrusted_bytes |
| `model_calls` | token usage per purpose | purpose CHECK (leader/worker/…); status |
| `engagement_budgets` | §66 limits | per-engagement UNIQUE |
| `engagement_usage` | §66 counters | atomic upsert increments |
| `events.dedup_key` | §65 idempotency | unique index (NULLs allowed for legacy rows) |

## State machines (all deterministic, mirrored by CHECKs where noted)

* **AgentRun**: `CREATED -> INITIALIZING -> RUNNING <-> PAUSED/WAITING ->
  COMPLETED | FAILED | CANCELLED`.
* **Task**: `CREATED -> QUEUED -> READY -> RUNNING -> COMPLETED | PARTIAL |
  FAILED | CANCELLED | EXPIRED`, plus `WAITING` (dependencies),
  `RECOVERY_PENDING` (crash, §64) and `RUNNING -> QUEUED` (bounded retry,
  §44). Timestamps are set by transition semantics, not callers.
* **Hypothesis**: `PROPOSED -> ACTIVE -> TESTING -> SUPPORTED -> CONFIRMED`
  with `DISPROVED`/`ABANDONED` exits. `CONFIRMED` is reachable only via
  verification evidence (§55); a hypothesis is never a finding without it.

## Verification and finding promotion (§55)

`HYPOTHESIS -> TESTING -> SUPPORTED -> VERIFICATION -> CONFIRMED FINDING`:
the hypothesis engine gates CONFIRM on `viaVerification` (granted only for
VERIFICATION-type tasks), then promotes an idempotent finding row.
