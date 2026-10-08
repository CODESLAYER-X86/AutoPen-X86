# Architecture Overview

## What this is

Aegis is an autonomous web-security testing and CTF-solving platform. Part 1 (this
codebase) delivers the foundation: repository, runtime, data model, security
boundaries and core contracts. Later parts (2–8) will build the autonomous agent
loop, HTTP/browser workers, vulnerability engines, knowledge retrieval and
reporting on top of these boundaries.

The system is NOT a Burp Suite clone. It is a security-reasoning platform:

* a **strategic LLM** plans, prioritises and decides when to stop,
* **tactical LLMs** execute narrowly scoped task packets,
* **deterministic tools** do all parsing, transport and measurement,
* **PostgreSQL + object storage** own all state — never the model context.

The LLMs are reasoning components, never the source of truth.

## Monorepo layout

```
apps/
  api/    Fastify HTTP API (composition root)
  web/    React + Vite frontend
packages/
  shared/       prefixed IDs, typed errors, domain enums (isomorphic)
  contracts/    zod API schemas shared by frontend and backend (isomorphic)
  config/       zod-validated environment configuration
  logging/      structured JSON logging + secret redaction
  security/     scope checker, scrypt passwords, encrypted secret store
  database/     pg pool, hash-verified migrations, repositories
  events/       event bus abstraction (in-memory + persisting)
  queue/        job queue abstraction (in-memory provider)
  model-runtime/ModelProvider interface, mock + Google providers, router
  tools/        tool registry, permission/scope gateway, parser.jwt
services/
  orchestrator/   engagement state machine + lifecycle transitions
  evidence/       immutable hash-addressed evidence + object store
  target-http/    HTTP worker interface (not implemented — Part 3)
  browser/        browser worker interface (not implemented — Part 4)
  worker-runtime/ tactical worker interface (not implemented — Part 2)
  knowledge/      knowledge retrieval interface (not implemented — Part 5)
tests/  unit / integration / security / e2e / fixtures
docs/   architecture / security / api / operations
scripts/db/  embedded PostgreSQL lifecycle + migrations
```

Dependency direction is strictly downward: `apps -> services -> packages ->
shared`. No cross-package imports outside these declared dependencies.

## Runtime composition

```
User -> Web UI -> Engagement API -> Orchestrator
                                        |
                          (Part 2: strategic model -> decisions
                           -> planner -> task compiler -> workers)
                                        |
                                  Tool Gateway
                                        |
                    scope check -> capability check -> execute
                                        |
                                   Target(s)
                                        |
                              Observation Engine (Part 3+)
                                        |
                    events / evidence / audit -> PostgreSQL
```

Part 1 implements everything down to the deterministic boundaries (scope,
tool gateway, lifecycle, evidence) and stops there. The autonomous loop
(`OrchestratorService.startRun`) exists as an explicit `NotImplementedError`.

## Process model

* `apps/api/src/server.ts` is the process entry: config validation, migrations,
  HTTP listen, graceful shutdown.
* `buildApp()` (same package) is the testable factory used by all integration
  and e2e suites via `fastify.inject` and real sockets.
* The frontend dev server proxies `/api` to the API so no CORS is needed.

## Key decisions

| Decision | Rationale |
|---|---|
| Fastify 4 + TypeScript ESM | spec §4; typed, fast, plugin encapsulation for auth scopes |
| PostgreSQL via `pg` + raw SQL repositories | spec §4: relational source of truth, no ORM magic in security paths |
| App-generated prefixed IDs (`ENG_…`) | spec §15: auditability across logs, events, and database |
| Hash-verified migrations | tamper detection on the schema itself |
| zod contracts shared FE/BE | spec §28: single source of truth for API shapes |
| Embedded PostgreSQL in dev | reproducible local runs without root privileges |
| In-memory queue/event/limiter providers | interface-first; Redis/BullMQ can replace without call-site changes |

See `boundaries.md` for the security-relevant architecture, `data-model.md`
for the schema and `events.md` for the event vocabulary.
