# Architecture Overview

## What this is

Aegis is an autonomous web-security testing and CTF-solving platform. Part 1
delivered the foundation: repository, runtime, data model, security
boundaries and core contracts. **Part 2 (this state) adds the Agent
Operating System**: one strategic reasoning leader, disposable tactical
workers, deterministic orchestration, structured task creation,
hypothesis-driven investigation, token/quota management, scheduling,
anti-loop protection, verification, crash recovery and the autonomous
decision loop. Later parts (3–8) will add HTTP/browser tools, vulnerability
engines, knowledge retrieval and reporting on top of these boundaries.

The system is NOT a Burp Suite clone. It is a security-reasoning platform:

* a **strategic LLM** plans, prioritises and decides when to stop,
* **tactical LLMs** execute narrowly scoped task packets,
* **deterministic tools** do all parsing, transport and measurement,
* **PostgreSQL + object storage** own all state — never the model context.

The LLMs are reasoning components, never the source of truth.

## Monorepo layout

```
apps/
  api/    Fastify HTTP API (composition root; wires the agent engine registry)
  web/    React + Vite frontend (agent + findings tabs)
packages/
  shared/       prefixed IDs, typed errors, domain enums (isomorphic)
  contracts/    zod API + agent decision/worker schemas (isomorphic)
  config/       zod-validated environment configuration
  logging/      structured JSON logging + secret redaction
  security/     scope checker, scrypt passwords, encrypted secret store
  database/     pg pool, hash-verified migrations, repositories (27 tables)
  events/       event bus abstraction (in-memory + persisting, dedup keys)
  queue/        job queue abstraction (in-memory provider)
  model-runtime/ModelProvider interface, mock + Google providers, router
  tools/        tool registry, permission/scope gateway, parser.jwt
services/
  orchestrator/   engagement state machine + agent launcher bridge
  agent/          THE AGENT OPERATING SYSTEM (Part 2):
                  loop engine, leader runtime, decision validator,
                  task compiler, scheduler, hypothesis engine, quota
                  manager, anti-loop, recovery, metrics, prompts
  evidence/       immutable hash-addressed evidence + object store
  target-http/    HTTP worker interface (not implemented — Part 3)
  browser/        browser worker interface (not implemented — Part 4)
  worker-runtime/ tactical worker runtime (REAL since Part 2: bounded
                  tool loop, structured turns, NEEDS_* statuses)
  knowledge/      knowledge retrieval interface (not implemented — Part 5)
tests/  unit / integration / security / e2e / fixtures
docs/   architecture / security / api / operations
scripts/db/  embedded PostgreSQL lifecycle + migrations
```

Dependency direction is strictly downward: `apps -> services -> packages ->
shared`. No cross-package imports outside these declared dependencies. The
orchestrator depends on the agent only through the `AgentLauncher` interface
(no package cycle).

## The Agent Operating System (Part 2)

```
                 STRATEGIC MODEL (configured, never hard-coded)
                        |
                        v
                STRATEGIC CONTEXT (projection, §6-§8)
                        |  trusted state + untrusted target data (labeled)
                        v
                LEADER DECISION (9-value union, schema-validated)
                        |
                        v
          DECISION VALIDATOR (§10: semantic/engagement/scope/
                        |     permission/resource/duplicate layers)
                        v
                   TASK COMPILER (§13-§15: retrieval, compact packets,
                        |     context splitting when over budget)
                        v
                   TASK SCHEDULER (§19/§32-§33/§40: dependencies,
                        |     priorities, quota-aware, retries)
                        v
              TACTICAL WORKER RUNTIME (§11-§17: bounded tool loop,
                        |     allow-list only, NEEDS_* statuses)
                        v
                   TOOL GATEWAY (§69: the ONLY path to tools)
                        |
                        v
                      TARGET
                        |
                        v
            RESULT NORMALIZER (§42: observations, dedup,
                        |     hypothesis updates, evidence links)
                        v
     HYPOTHESES / TEST REGISTRY / DEAD ENDS / FINDINGS (persisted)
                        |
                        v
            STRATEGIC CONTEXT REBUILD -> next cycle
```

The loop (`services/agent/src/loop.ts`) is an **explicit event-driven state
machine** — `step()` performs exactly one deterministic tick (control check →
stop conditions → dependency resolution → dispatch → anti-loop → leader
cycle), never uncontrolled recursion. Every decision cycle is persisted with
an input-state hash (§31) so autonomous behaviour is reproducible.

## Runtime composition

```
User -> Web UI -> Engagement API -> Orchestrator
                                        |
                          Agent Engine Registry (per engagement)
                                        |
                    strategic model -> decisions -> task compiler
                                        -> scheduler -> workers
                                        |
                                  Tool Gateway
                                        |
                    scope check -> capability check -> execute
                                        |
                                   Target(s)
                                        |
                    events / evidence / audit -> PostgreSQL
```

`OrchestratorService.startRun` now delegates to the injected `AgentLauncher`
(implemented by `AgentEngineRegistry` in the API composition root); with no
launcher wired it still fails with the honest `NotImplementedError`.

## Process model

* `apps/api/src/server.ts` is the process entry: config validation, migrations,
  HTTP listen, graceful shutdown.
* `buildApp()` (same package) is the testable factory used by all integration
  and e2e suites via `fastify.inject` and real sockets.
* Agent engines run in-process (one per engagement, registry-managed) and are
  restartable: all state lives in the database, and `attach()` + crash
  recovery rebind after a restart (spec Part 2 §63).
* The frontend dev server proxies `/api` to the API so no CORS is needed.

## Key decisions

| Decision | Rationale |
|---|---|
| Fastify 4 + TypeScript ESM | spec §4; typed, fast, plugin encapsulation for auth scopes |
| PostgreSQL via `pg` + raw SQL repositories | spec §4: relational source of truth, no ORM magic in security paths |
| App-generated prefixed IDs (`ENG_…`, `RUN_…`, `HYP_…`) | spec §15: auditability across logs, events, and database |
| Hash-verified migrations | tamper detection on the schema itself |
| zod contracts shared FE/BE | spec §28: single source of truth for API shapes |
| Embedded PostgreSQL in dev | reproducible local runs without root privileges |
| In-memory queue/event/limiter providers | interface-first; Redis/BullMQ can replace without call-site changes |
| Discriminated-union decision schema, strict | model output fails closed; injections (extra fields) never survive |
| AgentLauncher interface bridge | orchestrator stays model-free; agent stays lifecycle-free |
| Saturating confidence strategy (replaceable) | §25: heuristic now, swappable math later |
| Deterministic fingerprints for dedup | §29: no LLM in duplicate detection |

See `boundaries.md` for the security-relevant architecture, `data-model.md`
for the schema, `events.md` for the event vocabulary, and
`docs/security/threat-model.md` for the prompt-injection analysis.

## Part 3 — the interaction layer

Part 3 adds the deterministic interaction layer between the agent system
and authorized web targets (spec Part 3 §0): the LLM decides **what** to
investigate; the tool layer determines **how** the operation runs.

```text
                    STRATEGIC LEADER
                           |
                    TASK SCHEDULER
                           |
                      WORKER RUNTIME
                           |
                    TOOL REGISTRY  (gateway: policy/scope gates)
                           |
              +------------+-------------+
              |                          |
        HTTP ENGINE               BROWSER SERVICE
        (fetch + SSRF policy)     (Playwright, identity-isolated contexts)
              |                          |
              +------ TRAFFIC RECORDER --+
                         |
              normalized HttpRequest/HttpResponse records
              (shared by both paths — spec §14)
                         |
              evidence store + observation events
```

Key properties:

* **One shared request model** (§14): browser captures are promoted into the
  same `http_requests`/`http_responses` records the HTTP engine writes, so
  captured traffic can be replayed and mutated.
* **SSRF defence in depth** (§49-§52): URL validation (scope) + network
  policy (scheme allowlist, DNS resolution + IP classification, loopback/
  private ranges denied in production, re-validated per redirect hop).
* **Identity isolation** (§3-§4, §29): one Playwright context per identity
  (anonymous included); cookies/storage never cross contexts; secrets live
  in the encrypted secret store and are injected at use time (§26).
* **Explicit truncation** (§48): response/WebSocket/download size limits
  record `truncated = true` — nothing is silently dropped.
* **MCP boundary** (§42): the internal tool registry + gateway remains the
  architecture; an MCP adapter is an optional transport in front of the
  same gateway, never a dependency.
* **Honest capabilities**: tools are registered with risk levels, zod
  input/output schemas, version + configuration version (§43, §46, §78),
  and every execution is audit-logged with redacted input.

Services added in Part 3: `@aegis/target-http` (engine, mutation, recorder,
HAR import, URL policy), `@aegis/session-manager` (identity auth state),
`@aegis/browser` (Playwright service), `@aegis/toolbox` (the real tool
implementations registered by the composition root).

---

# Part 4 — Security Reasoning Engine

Part 3 gave the platform hands. Part 4 gives it judgment: the deterministic
security-reasoning layer that transforms recorded observations (HTTP
exchanges, browser events, DOM snapshots, WebSocket messages, identities,
sessions) into a structured, skeptical, evidence-driven security model.

The central principle (spec Part 4 §0, §136):

> **Do not ask an LLM to rediscover structure that deterministic software
> can extract. And never treat an observation as a vulnerability.**

```text
raw observations (HTTP/browser/WS/DOM)
        |
        v
  observation normalizer (event-driven, §109)
        |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
  endpoint/parameter   identity/session   workflow/state
  extraction (§7-§18)  mapping (§20-§23)  reconstruction (§30-§35)
        |                  |                  |
        +--------+---------+--------+---------+
                 |                  |
                 v                  v
      attack-surface graph    data-flow engine (§37-§41)
      (nodes+edges, §4-§6)          |
                 |                  |
                 +--------+---------+
                          |
                          v
              security signal engine (§42-§43)
              (signals are NOT findings)
                          |
                          v
              hypothesis engine seam (§44-§47)
              (competing interpretations)
                          |
                          v
              test planner (§48-§50, §118)
              (deterministic fingerprints,
               preconditions, information gain)
                          |
                          v
              differential engine (§24-§28)
              (semantic comparison, volatile filtering)
                          |
                          v
              verification engine (§70-§75)
              (skeptical: tries to REFUTE first;
               alternatives preserved; dead ends recorded)
                          |
                          v
              leader projection (§120)
              (compact, trust-separated)
```

Key properties:

* **OBSERVATION ≠ VULNERABILITY** (§136): the pipeline is
  observation → signal → hypothesis → test → evidence → verification →
  finding. Nothing is promoted without the full chain; the verifier
  actively seeks alternative explanations (public object, cache, shared
  access, non-reproduction) and records them.
* **Deterministic-first** (§83): endpoints, parameters, value
  characteristics, JWT structure, object candidates, workflows, differentials
  and fingerprints are computed by parsers — the LLM only interprets,
  prioritizes and decides.
* **Idempotent ingestion** (§111): every derived record is keyed by a
  deterministic fingerprint; reprocessing an event never duplicates
  endpoints, parameters, matrix cells, signals or flows.
* **Failure isolation** (§112): a crashing extractor records a
  `reasoning_failures` row and processing continues — the engagement never
  fails because the reasoning layer hiccuped.
* **Trust separation** (§115-§116): all target-derived text (signal
  summaries, canonical paths, mutation values) is rendered inside the
  leader prompt's `UNTRUSTED_TARGET_DATA` delimiters; counts and ids stay
  trusted. Scope, policy, limits and identity access remain deterministic
  and outside LLM control (§132).
* **Resource limits** (§113): graph nodes/edges, signals, parameters,
  endpoints, comparison bytes and mutation candidates are all capped.

Services added in Part 4: `@aegis/reasoning` (the engine: processor,
extractors, differential, signals, hypotheses, test planner, mutation
strategies, token analysis, object model, workflow engine, data-flow,
graph, verification, prioritization, projection, limits) plus three
read-only worker tools in `@aegis/toolbox` (`reasoning.query` §80,
`differential.compare` §118, `verification.evaluate` §72) and 16 API
routes under `/api/engagements/:id/reasoning/*`.

---

## Part 5 — Security Knowledge & Web Research System

The knowledge subsystem is an **advisor** for the agents, never an
authority over scope or policy. It answers "what testing strategy is
relevant to this behavior?" without flooding model context, trusting
arbitrary websites, or losing provenance.

```text
              LEADER / WORKER
                     |
                     v
             Knowledge Request (structured, §17)
                     |
                     v
             Knowledge Router (§103/§105)
             LOCAL → CURATED → LIVE escalation
                     |
        +------------+------------+
        v            v            v
   Local Index   Web Search   Case Memory
   (FTS + vectors) (bounded)  (CTF write-ups)
        |            |
        +------+-----+
               v
        Content Pipeline (§115)
        FETCH → PARSE → SANITIZE → METADATA
        → CHUNK → HASH → INDEX → EMBED
               |
       +-------+-------+
       v               v
  Keyword Index    Vector Index
  (PG full-text)  (hashed embeddings)
       |               |
       +-------+-------+
               v
            Reranker (§22/§69)
   relevance + trust + freshness + context
   + specificity - duplicate penalty
               |
               v
     Token Budget Filter (§62/§63)
               |
               v
   Compact Knowledge Packet (§61)
   + <UNTRUSTED_EXTERNAL_KNOWLEDGE> (§41/§50)
               |
               v
            Agent Model
```

Key properties:

* **KNOWLEDGE ≠ EVIDENCE, KNOWLEDGE ≠ AUTHORITY** (§135): knowledge
  recommends techniques; only target observations become evidence.
  Retrieved content can never modify scope, permissions or policy (§125).
* **Hybrid retrieval** (§15-§16): PostgreSQL full-text search for exact
  security terminology + deterministic hashing embeddings for conceptual
  similarity; results merged, deduplicated by content hash and reranked
  with configurable weights (§69).
* **Prompt-injection isolation** (§48-§52, §128): external knowledge is
  rendered inside explicit `<UNTRUSTED_EXTERNAL_KNOWLEDGE>` delimiters
  with a knowledge-usage policy in the system prompt; trusted metadata
  (source, trust level, relevance) stays outside the delimiters.
  Sanitization removes scripts and never executes downloaded content.
* **Provenance preserved** (§7, §60, §67): every chunk keeps document id,
  source, URL and section; identical content under a different URL links
  to the canonical document instead of duplicating; changed sources
  create new VERSIONS, history is never overwritten (§25).
* **Bounded live research** (§26-§33, §72, §83): a dedicated fetcher with
  SSRF defence (DNS resolution before connection, loopback/private
  denied by default), per-source rate limits, size limits with explicit
  truncation flags, per-day budgets and research task budgets (searches,
  pages, bytes, time, tokens). No web search provider configured →
  honest empty results, never pretend searches (§104).
* **Trust as a ranking factor** (§23, §129): OFFICIAL > TRUSTED_TRAINING
  > RESEARCH > CTF > COMMUNITY > UNTRUSTED; trust never overrides policy.
* **Freshness without collapse** (§24, §130): current material outranks
  old, but historical CTF write-ups keep value; freshness never
  overwhelms technical relevance.
* **Case memory separation** (§37): engagement evidence stays in Part 2/4
  state; CTF write-ups are a separate corpus with structured fields and
  deterministic pattern extraction (§42: technique / precondition /
  signal / test pattern / verification / false-positive).
* **Source disagreement preserved** (§73, §111): corroborated claims and
  disagreements are surfaced to the leader — never silently averaged.
* **Model-efficient delivery** (§61-§63, §87-§88, §109): the leader
  receives a bounded packet (default ≤ 2500 tokens) with primary +
  one corroborating source per concept; workers get 2-6 chunks via the
  knowledge.* tools; adaptive sizing honors the TPM budget.
* **Auditable retrieval** (§85-§86): every query, result row, research
  task, fetched source and packet creation is persisted and evented.
* **Retrieval quality measured** (§96-§98): Recall@K, Precision@K, MRR,
  NDCG, duplicate rate and agent-utility metrics over query rows — the
  objective is USEFUL retrieval, not maximum retrieval.

Integration seams:

* Part 2 leader: `KnowledgeContextProvider` (§120) builds the compact
  packet from active hypotheses — trusted metadata in the trusted
  projection, excerpts in the untrusted section.
* Part 4: the shared security taxonomy aligns knowledge categories with
  hypothesis categories; `knowledge_references` cross-links hypotheses
  with techniques and CVE/CWE/OWASP references (§59).
* Workers: `knowledge.search`, `knowledge.similar_cases`,
  `knowledge.search_web`, `knowledge.fetch` tools (§33-§36) behind the
  gateway — live web tools require the explicit `knowledgeWeb`
  permission and fail closed without it (§84).

# Part 6 — Autonomous Pentest & CTF Engine

The autonomous engine (`services/autonomous-engine`, package `@aegis/autonomous`)
combines everything built in Parts 2–5 into one **persistent, restartable
loop** (spec Part 6 §1, §7):

```
OBSERVE -> MODEL -> HYPOTHESIZE -> PRIORITIZE -> PLAN -> VALIDATE ->
EXECUTE -> OBSERVE -> COMPARE -> VERIFY -> UPDATE -> REPLAN
```

The LLM never constructs an unrestricted network operation (§1): every task
flows through the Part 2 compiler → scheduler → tool gateway, with scope,
policy, quota and duplicate gates enforced at every layer (§47). The engine
itself is **model-free** in its deterministic layers — candidates,
differentials, verification verdicts and stop decisions are computed by
code; the strategic model decides priorities through the validated Part 2
decision path.

## Module map (spec §5)

```
services/autonomous-engine/src/
├── engine/          engagement-engine (§73 facade), lifecycle-manager (§6),
│                    loop-controller (§8 event-driven), state-machine, ports
├── reconnaissance/  recon-planner (§9), asset-discovery (§10 passive),
│                    endpoint/parameter-discovery (§11 bounded active),
│                    auth-discovery, workflow-discovery, technology-fingerprint
├── reasoning/       hypothesis bridge (§14-§16), prioritizer (§17),
│                    strategy engine (§32), branch manager (§65-§66),
│                    anomaly analyzer (§24)
├── planning/        task planner (§38 test candidates -> tasks),
│                    dependency planner (§36-§37), cost estimator
├── execution/       execution controller (§55 leases), worker dispatcher,
│                    retry manager (§40), recovery manager (§55)
├── analysis/        observation analyzer, differential engine (§18-§19),
│                    dataflow (§23), state analyzer (§21-§22),
│                    evidence correlator (§25)
├── verification/    verifier (§26), confidence engine (§28),
│                    false-positive filter (§27), reproduction engine
├── ctf/             ctf-engine (§4), clue analyzer (§29), riddle engine,
│                    flag-condition analyzer (§31), challenge memory (§34)
├── stopping/        stop evaluator (§50), budget evaluator (§42),
│                    coverage evaluator (§51)
├── graph/           attack-surface graph projection (§12-§13)
├── timeline/        live agent timeline (§53)
└── eval/            benchmarks (§79) + benchmark runner (§84 metrics)
```

## Key properties

- **Phases, not process memory** — engine state (`autonomous_engine_states`)
  is persisted per engagement with optimistic-concurrency versioning (§6/§56).
  A restart resumes from the DB (§54): incomplete tasks are recovered, the
  loop re-enters at the persisted phase.
- **Event-driven loop** (§8) — the loop controller subscribes to the event
  bus (task completions, reasoning ingestion, hypothesis updates,
  verifications) plus a bounded maintenance interval for time-based
  transitions; all engine mutations serialize through one queue (§56).
- **Deterministic recon bootstrap** (§9) — scope validation → passive
  discovery → bounded active discovery (§11: reason/scope/gain/cost/risk on
  every task) → session init → application mapping. Never vulnerability
  testing before a baseline exists.
- **Candidates → hypotheses → branches** (§14-§16, §65) — Part 4 signal
  groups are consumed into hypotheses with COMPETING alternatives
  preserved; branches group interpretations and are pruned, never deleted.
- **Test candidates → tasks** (§38, §20) — Part 4 planned tests compile into
  worker tasks through the SAME compiler path as leader decisions; workers
  execute the structured mutation plan via `http.mutate`.
- **Verification bridge** (§26, §58) — VERIFIED → hypothesis CONFIRM
  (enforced viaVerification) → promoted finding enriched with the §28
  confidence model; REFUTED → disproved + dead end + branch prune.
  A finding can never be VERIFIED without verification evidence.
- **CTF mode** (§4, §29-§31) — clues → deterministic riddle interpretation →
  branches → flag conditions; a challenge only becomes SOLVED with
  pattern-observed flag evidence, never because a vulnerability was found.
- **Crash recovery with leases** (§55) — tasks are claimed via conditional
  UPDATE (one owner at a time); expired leases are swept; state-changing
  tasks are MARK_FAILED, never blindly retried.
- **Stop conditions** (§50) — objective completed, no useful hypotheses,
  budget exhausted, scope risk, repeated failure, diminishing returns —
  all observable as `STOP_CONDITION_MET` events.
- **Benchmarks** (§79-§84) — offline fixture benchmarks with known ground
  truth (lab IDOR + negative control; four CTF challenge types) measuring
  time-to-finding, false-positive rate, duplicate rate, per-finding
  efficiency and CTF solve rate.

## Part 7 — Verification, Reporting & Evaluation

The epistemic reliability layer: OBSERVED TRUTH, INFERRED TRUTH and
REPORTED TRUTH are never conflated (§101). `services/verification-reporting`
(`@aegis/vr`) converts autonomous output into verified findings, reproducible
evidence, confidence assessments, professional reports and agent benchmarks.

**Architecture:**

```text
AUTONOMOUS ENGINE
        │
        ▼
CANDIDATE FINDING ── finding-lifecycle (§4-§5, guarded + audited)
        │
        ▼
VERIFICATION PLANNER (§8: strategies, controls, expected result, §7 sufficiency gate)
        │
   ┌────┼────────────────┐
   ▼    ▼                ▼
REPRODUCTION   CONTROL     ALTERNATIVE
(§12, real     TESTS (§9,  EXPLANATIONS (§10)
 replays       authz-matrix
 through the   differentials)
 controlled
 HTTP port)
   │    │                │
   └────┼────────────────┘
        ▼
EVIDENCE GRAPH (§21-§23, immutable + hashed)
        ▼
CONFIDENCE ENGINE (§15-§16, deterministic, ≠ severity)
        ▼
SEVERITY ENGINE (§17-§18, CVSS 3.1 calculator)
        ▼
FINDING SERVICE + DEDUPLICATION (§6, §19-§20)
        │
   ┌────┴─────────────┐
   ▼                  ▼
HUMAN REVIEW      REPORT BUILDER (§31: normalize → dedup → severity →
(§67-§68,          confidence → evidence selection → redaction →
 audited, never    composition → validation → export)
 silent overwrite)     │
   │                  ▼
   ▼            HTML / Markdown / JSON / PDF (§63, hash-manifested §66)
FINAL FINDING
                     │
                     ▼
              EVALUATION ENGINE (§39-§92: scenarios with hidden ground
              truth, precision/recall/FPR, safety benchmarks, scorecard,
              regression gates, golden runs)
```

**Key properties:**

- **Verification is a separate system** (§2) — the verifier that confirms a
  hypothesis is not the reasoning that created it; controls, alternative
  explanations and reproduction are searched for REFUTATIONS, not
  confirmations.
- **Never "LLM says vulnerability → finding"** — VERIFIED requires the
  deterministic policy (§71: class-specific rules; §72: stricter gate for
  high-risk findings), eliminated alternatives, and evidence-sufficiency.
  INCONCLUSIVE is a first-class verdict (§74: know when you do not know).
- **Confidence ≠ severity** (§16, §18) — the confidence engine scores
  evidence dimensions; the severity engine computes CVSS 3.1 deterministically
  (model may supply inputs, never scores). Contradictory evidence DECREASES
  confidence (§82).
- **Deduplication is deterministic** (§19-§20) — same root cause + endpoint
  shape family merge into one finding with accumulated endpoints; duplicates
  are kept (never deleted) as false-positive data.
- **Report safety** (§24, §65, §73) — deterministic redaction (cookies,
  bearer tokens, JWTs, API keys, emails, private keys) before composition;
  validation REJECTS reports with unredacted secrets, unsupported claims,
  verified findings without evidence or nonexistent evidence references
  (hallucination guard, §76). Executive reports exclude exploit detail.
- **Retesting re-verifies the security property** (§37) — never a raw request
  replay; outcomes FIXED / PARTIALLY_FIXED / STILL_PRESENT.
- **Evaluation is queryable** (§59) — runs, scenarios, expected/observed
  findings, metric rows, events and model-config snapshots are database rows,
  never only a final JSON blob; scorecard (§87) + release gates (§88-§89) +
  golden runs (§90, behavioral outcomes only, §91).
- **Local fixtures only** — evaluation scenarios boot the in-service
  deterministic fixture (never external targets); out-of-scope hosts are
  DISCOVERED but NOT EXECUTED (§77), prompt injection stays inert (§78).
