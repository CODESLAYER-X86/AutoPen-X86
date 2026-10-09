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
