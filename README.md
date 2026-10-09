# Aegis Platform

Autonomous web-security testing and CTF-solving platform.
**Part 1 of 8: foundation, repository, runtime, data model, security
boundaries and core contracts — implemented, built and tested.**
**Part 2 of 8: the Agent Operating System — strategic leader, tactical
workers, task compiler, scheduler, hypothesis engine, autonomous loop —
implemented, built and tested.**
**Part 3 of 8: the interaction layer — HTTP engine with SSRF defence,
controlled mutation + replay, Playwright browser service with
identity-isolated contexts, network capture promoted to shared request
records, multi-identity sessions, HAR import, artifact retrieval —
implemented, built and tested.**
**Part 5 of 8: the security knowledge & web research system — hybrid
retrieval, curated sources, CTF case memory, bounded live research,
provenance and prompt-injection isolation.**
**Part 6 of 8: the autonomous pentest & CTF engine — a persistent,
restartable loop (recon → model → hypothesize → test → verify → replan)
with DB-leased task recovery, competing-hypothesis branches, verification
bridging, CTF riddle reasoning with flag-condition evidence, stop
conditions, human approvals and an offline benchmark suite.**
extraction (endpoints/parameters/authorization matrix/objects/workflows/
data flows), security signals, competing hypothesis candidates, test
planning with information gain, semantic differential testing, skeptical
verification with alternative explanations — implemented, built and
tested.**

> **Authorized use only.** This platform is built for authorized penetration
> testing, local security laboratories, intentionally vulnerable
> applications and CTF environments. Every engagement requires an explicit,
> deterministic scope; nothing outside that scope can be contacted by any
> tool, worker, or model decision.

## What Part 1 includes (real, runnable)

- **Monorepo** (npm workspaces, TypeScript ESM): Fastify API, React+Vite UI,
  10 packages, 6 services, hash-verified SQL migrations (12 in Part 1)
- **Deterministic scope enforcement** — allowlist checker (hosts, domains,
  ports, schemes, exclusions), applied to every target and every network
  tool call; the model cannot bypass it
- **Engagement lifecycle** — PENTEST/CTF modes, state machine
  (DRAFT→READY→RUNNING⇄PAUSED→COMPLETED/FAILED/CANCELLED), events, audit
- **Auth** — scrypt passwords, hashed bearer tokens, per-route ownership
  (404 for cross-tenant), rate limiting, security headers
- **Evidence** — immutable, SHA-256-addressed object store with tamper
  verification and derived-evidence chains
- **Secrets** — AES-256-GCM secret store; DB/logs hold only `SEC_…`
  references; redaction engine over all structured logs
- **Abstractions for Parts 2–8** — tool registry + permission/scope
  gateway (1 real tool: `parser.jwt`), model provider interface (mock +
  Google REST), event bus, job queue, orchestrator, worker interfaces

## What Part 2 adds (real, runnable)

- **Agent Operating System** (`services/agent`): leader runtime, decision
  validator (7 deterministic layers), task compiler (compact packets,
  retrieval, context splitting), dependency-aware + quota-aware scheduler,
  hypothesis engine (competing hypotheses, branching, budgeted),
  result normalizer, anti-loop + oscillation detection, crash recovery,
  metrics, and the **event-driven autonomous loop** (explicit state machine,
  deterministic stop conditions — never uncontrolled recursion)
- **Real tactical worker runtime** (`services/worker-runtime`): bounded
  tool loop, allow-list-only tool requests, structured turns, NEEDS_*
  statuses, per-attempt persistence
- **9-value strategic decision vocabulary** — strict discriminated-union
  zod schemas; malformed/injected model output fails closed
- **Prompt trust separation** — every prompt is five labeled sections;
  target-derived text only ever appears inside
  `<UNTRUSTED_TARGET_DATA>` delimiters; persisted messages record
  `untrusted_bytes` for audit
- **Hypothesis-driven reasoning** — persistent hypotheses with
  evidence-event confidence updates, dead-end memory, test-registry
  fingerprint dedup, verification-gated finding promotion
  (HYPOTHESIS→TESTING→SUPPORTED→VERIFICATION→CONFIRMED FINDING)
- **Quota + budget management** — RPM/TPM/RPD sliding windows, separate
  token budgets per purpose (leader/worker/knowledge/summarization/
  verification), per-engagement resource budgets
- **15 new tables** (27 total), full HTTP API for runs/tasks/hypotheses/
  strategies/dead-ends/observations/findings/metrics + audited human
  overrides + crash recovery endpoint
- **Web UI**: agent tab (run control, hypotheses, tasks, strategies, dead
  ends, metrics) and a real findings tab

## What Part 3 adds (real, runnable)

- **HTTP engine** (`@aegis/target-http`): normalized request/response
  model shared by engine AND browser capture; JSON/form/multipart/text/
  XML/binary bodies; redirect following with **per-hop scope + network
  re-validation**; response size limits with explicit truncation flags;
  per-engagement/per-host rate limiting + bounded concurrency
- **SSRF defence** (§49-§52): scheme allowlist, DNS resolution + IP
  classification (loopback/private/link-local denied in production,
  lab policy for fixtures), malformed-URL rejection
- **Controlled mutation + replay** (§19-§22, §69-§72): structured
  mutations (query/header/cookie/JSON-path/form/method/path) create NEW
  immutable requests; originals never change; scope re-validated on
  execution
- **Browser service** (`@aegis/browser`, Playwright): per-engagement
  browser, **one isolated context per identity** (anonymous included),
  16 deterministic actions with semantic selectors, structured event
  stream, network capture promoted into HTTP records, DOM snapshots +
  diffs, cookies/storage captured into the secret store (values never
  stored), downloads as untrusted sha256 evidence, WebSocket
  observation, screenshots, finally-style cleanup
- **Session manager** (`@aegis/session-manager`): identity → auth state
  (cookies/bearer/JWT/custom headers/browser storage), injection at use
  time, expiration detection (401/403/auth-redirect/logout) as
  observations — never auto re-authentication; login workflows recorded
  as reusable identity sessions
- **Toolbox** (`@aegis/toolbox`): 23 real tools — `http.request/replay/
  mutate`, `browser.navigate/click/fill/submit/snapshot/screenshot/…`,
  `websocket.observe`, `artifact.read/extract/search`, `har.import` —
  each zod-schema'd, risk-classified, versioned, audit-logged with
  redacted input (§43-§47, §78)
- **13 new tables** (40 migrations total), 20 new API endpoints, HAR
  import with scope filtering, tool-execution audit log

**383 automated tests** (unit / integration / security / e2e — including
real-Chromium browser suites against a local lab fixture app) + a
43-check smoke test, all green.


## What Part 4 adds (real, runnable)

- **Security reasoning engine** (`@aegis/reasoning`): transforms recorded
  traffic into a structured security model — endpoints canonicalized and
  deduplicated by fingerprint (`/api/orders/1` + `/api/orders/2` →
  `/api/orders/{param}`), parameter registry with deterministic value
  characteristics (UUID/JWT/timestamp/…) and semantic candidates,
  authorization matrix (identity × endpoint × object × outcome), object
  candidates with ownership, workflow reconstruction from observed
  sequences, data flows, and a persistent attack-surface graph
- **Security signals, not findings** (§136): the deterministic signal
  engine emits CROSS_IDENTITY_DIFFERENCE, CROSS_IDENTITY_OBJECT_REFERENCE,
  AUTH_STATE_CHANGE, REFLECTED_INPUT, ERROR_DISCLOSURE, TOKEN_PATTERN,
  STATE_TRANSITION_ANOMALY, UNUSUAL_RESPONSE_DIFFERENCE, … — every signal
  states it is not a conclusion
- **Hypothesis candidates with competing interpretations** (§44-§47): every
  suspicious signal yields a primary hypothesis PLUS alternatives (public
  object / shared access / cache), each with required evidence and
  distinguishing tests
- **Test planning** (§48-§50, §118): deterministic fingerprints, explicit
  preconditions (scope, identity, baseline, duplicate), expected
  information gain that ranks tests by how well they separate competing
  hypotheses — the Part 2 scheduler seam
- **Differential engine** (§24-§28): semantic JSON/HTML/binary comparison
  with volatile-field marking (timestamps/CSRF tokens marked, never
  deleted), structural diffs, similarity scoring
- **Skeptical verification** (§70-§75): tries to REFUTE first — anonymous
  access, caching, shared access, reproduction, baseline comparison —
  alternatives preserved for audit, dead ends recorded with reasons,
  INCONCLUSIVE is a valid outcome
- **Leader projection** (§120): compact, trust-separated security context
  (counts and ids trusted; target-derived strings inside
  UNTRUSTED_TARGET_DATA delimiters) feeding the Part 2 leader prompt
- **3 worker tools**: `reasoning.query` (§80 focused attack-surface view),
  `differential.compare`, `verification.evaluate` — all READ_ONLY,
  engagement-bound, gateway-gated
- **16 API routes** under `/api/engagements/:id/reasoning/*` + 11 new
  migrations (041-051, 51 total) + 103 new tests (486 total)

## What is explicitly NOT implemented yet (by design)

Reporting (Part 6+); test candidates are PLANNED deterministically — the
Part 2 leader/scheduler decides execution. Knowledge retrieval is REAL
since Part 5 (see below).

## What Part 5 adds (real, runnable)

* **Knowledge base**: 12-table data model — curated source registry
  (OWASP WSTG/ASVS/API Top 10, PortSwigger, MDN, RFCs, CTF feeds),
  versioned documents with provenance, semantic chunks with heading
  paths, structured security techniques, extracted CVE/CWE/OWASP
  references, query audit rows, persisted scored results, research
  tasks and an index-version marker.
* **Ingestion pipeline** (§115): HTML/Markdown/TXT/JSON/XML/PDF parsers
  (a dependency-free PDF text extractor), sanitization (scripts removed,
  code preserved), deterministic metadata extraction, semantic chunking
  (300-800 token targets, code blocks separate), content hashing,
  PostgreSQL FTS indexing and best-effort embeddings (failure keeps the
  document keyword-searchable).
* **Hybrid retrieval** (§15-§25): keyword (PG full-text) + semantic
  (deterministic hashing embeddings by default, Google embeddings
  optional), merged and deduplicated, reranked with configurable
  weights — relevance, trust, freshness (CTF-aware decay), context,
  specificity, duplicate penalty; corroboration detection and PRESERVED
  source disagreement.
* **Compact packets** (§61-§63): token-bounded (leader ≤ 2500, worker
  ≤ 1200 tokens), primary + one corroborating source per concept,
  provenance on every result; rendered inside
  `<UNTRUSTED_EXTERNAL_KNOWLEDGE>` delimiters with a knowledge-usage
  policy — prompt injection in public pages stays inert data.
* **Case memory** (§36-§42): CTF write-ups with structured fields and
  deterministic pattern extraction (technique/precondition/signal/test
  pattern/verification/false-positive); riddle clue → concept candidates
  (PATTERN_RETRIEVAL); EXACT_CASE_RETRIEVAL stays a distinct benchmark
  mode.
* **Bounded live research** (§26-§33, §72): SSRF-defended fetcher (DNS
  before connection, loopback/private denial, redirect re-validation,
  size/time/rate/daily budgets), research planner, trust-ranked source
  selection, relevant-section extraction, corroboration/disagreement
  — all audited; no configured search provider → honest empty results.
* **Agent integration** (§120): the leader context carries a compact,
  trust-separated knowledge packet derived from active hypotheses;
  workers call the four `knowledge.*` tools (live web tools fail closed
  without the `knowledgeWeb` permission, §84).
* **Evaluation** (§96-§98): Recall@K / Precision@K / MRR / NDCG /
  duplicate-rate metrics + agent-utility metrics surfaced on
  `/api/knowledge/status`; the §127 query set runs as a retrieval
  benchmark in the integration suite.

Honest boundaries: reporting (Part 6); the Part 6 engine will combine
Parts 2-5 into the long-running autonomous loop.
intelligence, authz mapping, differential testing), vulnerability-
specific workers, source analysis. Registered interfaces return clear
`NOT_IMPLEMENTED` errors; the UI marks them honestly.

## Quick start

```bash
npm install
cp .env.example .env
npx playwright-core install chromium   # browser binaries (Part 3)
npm run db:ensure      # starts embedded PostgreSQL on 127.0.0.1:5433
npm run db:migrate
npm run dev:api        # :4000
npm run dev:web        # :5173 (proxies /api)
```

Then: register → create project → create engagement → configure scope →
add target (out-of-scope targets are rejected) → start → *Start agent run*
(agent tab). With the default mock model providers the loop mechanics run
but decisions are rejected as non-JSON (honest mock behaviour); configure
`STRATEGIC_MODEL_PROVIDER=google` + `GOOGLE_API_KEY` for real reasoning.

## Commands

| Command | Purpose |
|---|---|
| `npm run typecheck` / `lint` / `build` | quality gates |
| `npm run test` | all 640+ tests (starts DB automatically) |
| `npm run test:unit / :integration / :security / :e2e` | individual suites |
| `npx tsx scripts/smoke.ts` | 77-check end-to-end smoke test |
| `npm run db:start / stop / ensure / migrate / reset` | embedded PostgreSQL lifecycle |

## Docs

- [Architecture overview](docs/architecture/overview.md)
- [Security boundaries](docs/architecture/boundaries.md)
- [Data model](docs/architecture/data-model.md)
- [Event system](docs/architecture/events.md)
- [Threat model](docs/security/threat-model.md)
- [API reference](docs/api/README.md)
- [Development guide](docs/operations/development.md)

## Stack

TypeScript (strict) · Fastify 4 · React 18 + Vite 5 · PostgreSQL (pg) ·
zod contracts (shared FE/BE) · vitest · typescript-eslint 9


## What Part 6 adds (real, runnable)

* **Autonomous engine** (`services/autonomous-engine`, ~40 modules): the
  §5 module map implemented as an event-driven, resumable loop — engine
  phases persisted in `autonomous_engine_states` with optimistic
  concurrency; a loop controller subscribing to the event bus with a
  bounded maintenance fallback; a deterministic recon bootstrap (scope
  validation → passive discovery → bounded active discovery → session
  init → application mapping).
* **Reasoning bridge**: Part 4 candidate groups consumed into hypotheses
  with COMPETING alternatives preserved (§16) and reasoning branches
  (§65: scored, budgeted, pruned-never-deleted); Part 4 planned tests
  compiled into worker tasks through the SAME validated compiler path as
  leader decisions (§38, §47) — the LLM never constructs an unrestricted
  network operation.
* **Verification bridge**: VERIFIED → hypothesis CONFIRM (viaVerification
  enforced) → finding promoted and enriched with the §28 confidence model
  (dimensions, level, reasons); REFUTED → disproved + dead end + branch
  prune. Findings carry category/confidence/impact/remediation and
  verification linkage — no VERIFIED without verification evidence.
* **Crash recovery with DB leases** (§55-§56): tasks claimed via
  conditional UPDATE (exactly one engine instance); lease expiry sweeps
  with policy separation — read-only tasks retry, state-changing tasks
  are failed, never blindly repeated.
* **CTF mode** (§4, §29-§31): challenge ingestion, deterministic riddle
  interpretation (lexicon — never treated as fact), knowledge-corroborated
  branches, flag-condition hypotheses, pattern-based flag detection with
  evidence; a challenge only becomes SOLVED on observed success-condition
  evidence.
* **Stop conditions + budgets + approvals** (§42, §48-§50): six stop
  conditions with observable events; budget thresholds with 80% warnings;
  human approval flow decided exactly once and audited.
* **Observability** (§52-§53, §85-§86): engagement dashboard tab with
  phase/branches/experimental registry/approvals/CTF context, and a live
  agent timeline rendering the full audit chain; every control action
  audited.
* **Evaluation framework** (§79-§84): five offline benchmarks with known
  ground truth (lab IDOR + workflow flaw + negative control; four CTF
  challenge types) measuring time-to-finding, false-positive rate,
  duplicate-test rate, per-finding request/token efficiency and CTF solve
  rate.
* 5 new migrations (062-066, 66 total) + task/test/finding column
  extensions; 15+ API routes; ~70 new tests (unit + integration + security
  + evaluation).

## What Part 7 adds (real, runnable)

**Part 7 of 8: verification, reporting & evaluation — epistemic reliability.**
The system converts autonomous output into verified findings, reproducible
evidence, deterministic confidence and severity, professional reports and
agent benchmarks. OBSERVED TRUTH, INFERRED TRUTH and REPORTED TRUTH are never
conflated (§101).

* **Verification is a separate system** (§2-§14): candidate findings get a
  deterministic verification plan (strategies, controls, expected result,
  required evidence) gated by evidence sufficiency (§7). Execution runs REAL
  reproduction replays through the same controlled, scope-validated HTTP
  infrastructure workers use (§12), control comparisons over the
  authorization matrix (§9), and mandatory alternative-explanation testing
  (§10) — a surviving simpler explanation blocks confirmation. INCONCLUSIVE
  is a first-class verdict (§74: the agent must know when it does not know).
* **Finding lifecycle** (§4-§5): CANDIDATE → UNDER_REVIEW →
  VERIFICATION_PENDING → VERIFYING → VERIFIED with honest INCONCLUSIVE /
  REJECTED / DUPLICATE / ACCEPTED terminals; every transition guarded and
  audited; rejected findings are kept as false-positive data (never deleted).
* **Deterministic scoring** (§15-§18): confidence is a weighted,
  configurable dimension score (evidence, reproducibility, controls, identity
  differentials, eliminated alternatives, consistency) with an explicit
  contradiction penalty — never severity, never a model number. Severity is
  a CVSS 3.1 calculator (exact FIRST formulas incl. Roundup and scope-changed
  impact); the model may supply inputs and justification, never scores.
* **Deduplication** (§19-§20): same root cause + endpoint-shape family merge
  into one finding with accumulated affected endpoints; duplicates kept.
* **Reporting pipeline** (§31-§34, §63-§66): normalize → dedup → severity →
  confidence → evidence selection → redaction → composition → validation →
  export. Reports are built from STRUCTURED verified facts (never LLM
  conversations); every claim maps to evidence ids and universal claims are
  rewritten to the tested scope (§33). Validation REJECTS unredacted
  secrets, unsupported claims, verified findings without evidence and
  nonexistent evidence references (hallucination guard, §76). Four
  dependency-free exporters (JSON §64 schema, HTML, Markdown §28 template,
  and a real PDF writer) with sha256 integrity manifests.
* **Human review + retest** (§67-§68, §37-§38): accept/reject/modify/retest/
  duplicate/severity-override/remediation — audited, never silently
  overwriting the agent's conclusion; the disagreement feed becomes
  improvement data. Retests re-verify the SECURITY PROPERTY (never a raw
  request replay) with FIXED / PARTIALLY_FIXED / STILL_PRESENT outcomes.
* **Evaluation system** (§39-§92): nine seeded scenarios with hidden ground
  truth (§41) covering the ENTIRE loop plus safety benchmarks — scope
  violations (§77: DISCOVERED but NOT EXECUTED), prompt-injection containment
  (§78), hallucinated-evidence rejection (§76), repetition memory (§79),
  resource awareness (§80), honesty under ambiguity (§74), CTF flag patterns
  (§52). Queryable metric rows (precision, recall, FPR, time-to-finding,
  tokens/requests per finding, duplicate rate — §43-§51), the §87 scorecard,
  release gates with configurable thresholds (§88-§89), model/prompt/tool
  comparison (§55-§58) and behavioral golden runs (§90-§91).
* **6 new migrations** (067-072, 72 total): finding lifecycle + CVSS +
  dedup columns, verification plans/results, reproduction plans, severity
  assessments, human reviews, retests, reports/exports and the 7-table
  evaluation database; model_calls gains prompt_version + context_size.
* **API**: 24 new routes (findings/verification/review/retest/reports +
  evaluations with scorecard/regression/compare). **Web**: reports tab
  (generation + validation issues + format downloads), Part 7 findings view
  (lifecycle, confidence, CVSS, verify/review/retest actions) and an
  evaluations page (scenario registry, run execution, scorecard bars).
* Tests: 675 passing (30 unit + 13 integration + 8 security for Part 7);
  smoke: 88 checks including the full Part 7 surface.

## Part 8 — Production Hardening (complete)

The final layer wraps the whole platform in deterministic operational security:

- **Zero-trust internals (§5)** — HMAC-signed, subject+capability-scoped internal service tokens; fail-closed verification.
- **API credentials (§11)** — API keys / PATs with owner, scopes, expiry, last-used, revocation; only SHA-256 hashes stored; the plaintext token is shown exactly once.
- **Scoped credential grants (§14-§15, §93)** — workers resolve secrets only through grants bound to engagement+identity+target+purpose with TTL; every resolution raises a CREDENTIAL_ACCESS event; kill switches at grant / engagement / platform level.
- **Tamper-evident audit chain (§85-§86)** — SHA-256 hash chain over canonical (jsonb key-order-safe) record content; advisory-locked appends; verification detects edits, reorderings and deletions.
- **Security events + incidents (§94-§96)** — deterministic events at control points; severity floors (operators cannot downgrade a CRITICAL category); HIGH/CRITICAL bursts auto-open incidents; timelines are reconstructable.
- **Circuit breakers (§97-§99)** — per (subject, category) violation counters; OPEN requires a human reset; agent and model breakers included.
- **Emergency stop (§89-§90)** — deterministic, LLM-independent, persisted across restarts; cancels pending tasks, revokes all grants, blocks every target-bound route with 403 EMERGENCY_STOP_ENGAGED.
- **Scope versioning (§91-§92)** — propose → diff → explicit activation → supersede; history immutable.
- **Transactional outbox (§44-§45)** — per-aggregate sequences, at-least-once delivery, bounded batches, visible ABANDONED state.
- **RLS defense in depth (§7)** — aegis_app role + tenant GUC policies on 10 tenant tables, tested with SET ROLE cross-tenant probes.
- **Artifact safety (§19-§20, §29-§31)** — magic-byte content detection, active-content quarantine, compression-bomb guards, archive traversal normalization, research egress guard.
- **Observability (§49-§52)** — /api/health (liveness), /api/ready (readiness + WAITING_FOR_RESOURCE), /api/metrics (security metrics snapshot).
- **Ops tooling (§62-§70, §115)** — `npm run backup` / `npm run restore` (verified restore with row-hash equality), `npm run deps:audit` (fails closed), 9 operational runbooks, hardened Dockerfile + compose (non-root, dropped caps, no docker socket).

**Tests:** 706 green (424 unit / 183 integration / 97 security / 2 e2e); 76 migrations; Part 8 adds 41 tests across the three suites including the verified-backup roundtrip and RLS cross-tenant probes. Honest boundary: the fastify 4→5 upgrade (HIGH advisory in the routing layer) is deliberately gated behind the Part 7 regression suite rather than shipped untested.
