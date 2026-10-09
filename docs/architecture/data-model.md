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

## Part 3 — interaction tables (migrations 028-040)

| Table | Purpose | Notes |
|---|---|---|
| `http_requests` | normalized request model (§16) | shared by engine + browser capture; redacted headers; provenance columns (§55) |
| `http_responses` | normalized response model (§17) | artifact refs to bodies, explicit `truncated` flag (§48) |
| `browser_contexts` | context registry (§3-§5) | status lifecycle CREATE→…→CLOSED/FAILED; per-identity |
| `browser_pages` | pages per context (§74) | closed_at bookkeeping |
| `browser_events` | structured event stream (§11) | bounded JSON payloads |
| `cookies` | cookie descriptors (§23) | values only as secret-store references (`COOKIE_REF_…`) |
| `storage_entries` | localStorage/sessionStorage (§24) | sensitive values redacted + referenced |
| `dom_snapshots` | normalized DOM captures (§32) | elements/forms/links/ARIA; DERIVED evidence linkage |
| `downloads` | captured downloads (§37) | sha256 + UNTRUSTED evidence reference |
| `websocket_connections` / `websocket_messages` | WS observation (§36) | direction, sizes, truncation flags |
| `tool_executions` | execution audit log (§44-§45, §78) | tool + configuration version, redacted input |
| `auth_workflows` | recorded login workflows (§28) | steps + resulting session |

State machine additions: **BrowserContext** `CREATE -> INITIALIZE -> READY ->
ACTIVE -> (PAUSED) -> CLOSING -> CLOSED | EXPIRED | FAILED` (§5).
**Session** gains `status_reason` (why it left ACTIVE, §27) and
`engagement_id` scoping.

---

# Part 4 — reasoning tables (migrations 041–051)

All derived state is idempotent by deterministic fingerprints (§111):

* `endpoints` — canonical attack surface (§7-§13): fingerprint
  (scheme|host|port|canonical-path), methods observed (never assumed),
  observed URLs, confidence category (OBSERVED / INFERRED / …),
  discovery source, `merged_into` for canonical dedup.
* `parameters` — registry across QUERY/PATH/JSON/FORM/MULTIPART/HEADER/
  COOKIE/WEBSOCKET (§14-§15): value characteristics, semantic candidates
  with confidence, sensitive names stored redacted.
* `authorization_matrix` — identity × endpoint × object_ref × action with
  the latest outcome (ALLOWED/DENIED/REDIRECTED/ERROR/UNKNOWN) (§23, §98).
* `workflows`, `workflow_states`, `workflow_transitions` — candidate
  reconstruction from observed sequences (§30-§35); transitions carry
  trigger summaries, identity, evidence and fingerprints.
* `data_flows` — source → transformations → sink relationships with
  deterministic correlation fingerprints (§37-§41).
* `security_signals` — the deterministic signal layer (§42-§43): type,
  source, endpoint/parameter refs, identities, object ref, confidence,
  bounded summary, status NEW → CONSUMED/SUPERSEDED.
* `object_candidates` — object model (§19, §96-§97): name, kind, example
  values, owner identity, lifecycle evidence.
* `attack_nodes`, `attack_edges` — persistent attack-surface graph (§4-§6).
* `differential_results` — semantic comparisons with structured summaries
  (status/schema/fields/values/similarity/volatile) (§25-§28).
* `verifications` — skeptical verdicts: checklist (IS_OBJECT_PUBLIC,
  IS_RESPONSE_CACHED, IS_DATA_ACTUALLY_SENSITIVE,
  IS_SHARED_ACCESS_LEGITIMATE, DOES_BEHAVIOR_REPRODUCE,
  DOES_BASELINE_DIFFER), alternatives with refuted flags, result payload
  with promotion decision (§70-§75).
* `reasoning_failures` — processor failures with event refs (§112).

Endpoint lifecycle (§10): DISCOVERED → OBSERVED → MAPPED/TESTING →
INTERESTING/VERIFIED or IGNORED (merged). Signal lifecycle: NEW →
CONSUMED (drove a hypothesis) / SUPERSEDED.

---

## Part 5 — Knowledge tables (migrations 052-061)

| Table | Purpose | Key constraints |
|---|---|---|
| `knowledge_sources` | Curated source registry (§5): OWASP WSTG/ASVS/API Top 10, PortSwigger, MDN, RFCs, CTF write-up feeds | `UNIQUE(name)`, trust ∈ OFFICIAL/TRUSTED_TRAINING/RESEARCH/CTF/COMMUNITY/UNTRUSTED |
| `knowledge_documents` | Documents with full provenance (§7-§8) and raw artifact references (§94) | `UNIQUE(canonical_url, version)`, hash-indexed; version history preserved via `is_latest`/`superseded_by` (§25) |
| `knowledge_chunks` | Semantic chunks with heading paths (§9-§12); code blocks separate (§56) | GIN full-text index over heading+content (§13) |
| `knowledge_chunk_embeddings` | Vectors with model + version + dimension (§14, §95) | chunk PK; per-model index — model changes are explicit reindexes |
| `security_techniques` | Structured techniques: preconditions, signals, test patterns, verification, false-positives (§43) | `UNIQUE(name)`; aligned with the Part 4 hypothesis taxonomy |
| `knowledge_references` | Extracted CVE/CWE/OWASP/RFC references + hypothesis cross-links (§57, §59, §76) | value-indexed; a CVE is knowledge, not target evidence |
| `knowledge_queries` | Retrieval audit + cache key (§65, §85) | cache-key indexed with TTL |
| `knowledge_results` | Persisted scored candidates with separate dimensions (§68, §97) | relevance/keyword/semantic/trust/freshness each 0..1 |
| `research_tasks` | Bounded research workflows (§71, §83) | status PENDING→RUNNING→COMPLETED/FAILED; budgets recorded |
| `research_sources` | Candidate sources considered/fetched per research task (§85) | trust level + selection reason retained |
| `knowledge_versions` | Active index generation marker (§95) | single active row; embedding model + chunker params |
| `knowledge_cache` | Compact packet cache (§65) | cache_key PK, TTL expiry |

Lifecycles:

* **Document ingestion** (§115-§116): PENDING → FETCHED → PARSED → INDEXED;
  EMBEDDING_FAILED keeps the document keyword-searchable; FAILED retains
  the raw artifact — the source is never lost.
* **Versioning** (§25): same URL + changed content → new version row,
  previous row `is_latest = false`, `superseded_by` set; identical
  content re-ingestion is idempotent (§111).
* **Duplicate content** (§67): same content hash at a different URL links
  to the canonical document (`duplicate_of` in the ingestion outcome);
  provenance of both URLs is retained.
* **Research task** (§71): PENDING → RUNNING → COMPLETED/FAILED; every
  outcome — including budget exhaustion — is persisted and published.

# Part 6 — Autonomous engine tables

| Table | Purpose | Lifecycle |
|---|---|---|
| `autonomous_engine_states` | Engine phase per engagement (§6) + mode, replan/cycle counters, waiting reason, stop reason, engine instance id | CREATED → INITIALIZING → RECON → MODELING → HYPOTHESIS_GENERATION → TESTING → ANALYSIS → VERIFICATION → REPLANNING → (loop); terminal COMPLETED/STOPPED/CANCELLED/FAILED; waiting WAITING_FOR_USER/RESOURCE/IDENTITY/QUOTA |
| `reasoning_branches` | Reasoning branches (§65): origin (SIGNAL/CTF_CLUE), focus, hypothesis_ids, score, pruned_reason | ACTIVE → PAUSED/PRUNED/DISPROVED/COMPLETED (history preserved) |
| `ctf_contexts` | Challenge title/description/hints + flag format + status (§29, §31) | UNSOLVED → PARTIAL/SOLVED |
| `ctf_clues` | Extracted clues with deterministic interpretations (§29) | NEW → ANALYZED → INTERPRETED → CONSUMED/DEAD_END |
| `flag_conditions` | Success-condition hypotheses + detection evidence (§31) | HYPOTHESIZED → SUPPORTED → DETECTED/REFUTED |
| `engagement_approvals` | Human approval records for high-risk tasks (§48-§49) | pending (decision NULL) → APPROVED/REJECTED exactly once |
| `benchmark_runs` | Evaluation framework runs with computed metrics (§79) | COMPLETED/SOLVED/STOPPED/FAILED |

Part 6 also EXTENDS existing tables:

- `tasks.lease_expires_at / leased_by / heartbeat_at` — DB-level lease
  ownership (§55): a task is claimed by exactly one engine instance via a
  conditional UPDATE; expired leases move to RECOVERY_PENDING (safe retry)
  or FAILED (state-changing, never blindly repeated).
- `tests.result / expected_signal / actual_signal / mutation` — the
  experimental verdict vocabulary (§60): SUPPORTED / DISPROVED /
  INCONCLUSIVE / BLOCKED / FAILED.
- `findings` — category, confidence + confidence_level + confidence_reasons
  (§28 — confidence is NOT severity), impact, remediation, verification_ids,
  target_refs, affected_endpoints/identities, mode; statuses extended with
  CANDIDATE/VERIFIED (§58: no VERIFIED without verification evidence).

## Part 7 — Verification, Reporting & Evaluation

**Migrations 067-072.** Findings gain the full Part 7 lifecycle (§4-§5:
CANDIDATE → UNDER_REVIEW → VERIFICATION_PENDING → VERIFYING → VERIFIED with
honest INCONCLUSIVE / REJECTED / DUPLICATE / ACCEPTED alternatives; rejected
findings are never deleted — false-positive data), the CVSS representation
(§18: version, vector, base/temporal/environmental scores, source =
CVSS_CALCULATOR | HUMAN_OVERRIDE — separate from confidence), dedup_key +
duplicate_of linkage (§19-§20), retest_state (§38) and structured
observed/expected behavior.

| Table | Purpose |
| --- | --- |
| `finding_lifecycle_events` | Audited lifecycle transitions, engine AND human (§5, §67) |
| `finding_evidence_quality` | Per-finding evidence quality levels RAW→VERIFIED (§70) |
| `verification_plans` | Strategies, controls, expected result, required evidence + the §7 sufficiency snapshot (§8) |
| `verification_results` | Verdict, confidence, supporting AND contradictory evidence, tested alternatives (§10, §14) |
| `reproduction_plans` | Controlled step REFERENCES — never executable scripts (§12) |
| `severity_assessments` | CVSS calculator inputs and outputs, audited (§17) |
| `finding_reviews` | agent_status + human decision + resulting status; disagreement signal (§67-§68) |
| `retests` | §37 lifecycle: OPEN → FIXED / PARTIALLY_FIXED / STILL_PRESENT |
| `reports` / `report_exports` | §31 pipeline artifacts: claims, validation issues, redaction records, §66 manifest; per-format rendered artifacts (content-addressed sha256) |
| `evaluation_runs` | §42, §59 runs with reproducibility snapshots (§58) and golden flags (§90) |
| `evaluation_scenarios` + `evaluation_expected_findings` | §39-§41 scenario registry with hidden ground truth |
| `evaluation_observed_findings` | §47 TP/FP/FN/DUPLICATE matches |
| `evaluation_metrics` / `evaluation_events` | §59 queryable metric rows and the run audit chain |
| `evaluation_model_configs` | §55-§58 model/prompt/tool comparison snapshots |
| `evaluation_regression_checks` | §88-§89 release gates with configurable thresholds |

`model_calls` gains `prompt_version` + `context_size` (§83: exact quota
analysis and prompt-version evaluation).
