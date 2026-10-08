# Aegis Platform

Autonomous web-security testing and CTF-solving platform.
**Part 1 of 8: foundation, repository, runtime, data model, security
boundaries and core contracts — implemented, built and tested.**
**Part 2 of 8: the Agent Operating System — strategic leader, tactical
workers, task compiler, scheduler, hypothesis engine, autonomous loop —
implemented, built and tested.**

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

**297 automated tests** (unit / integration / security / e2e) + a
28-check smoke test, all green.

## What is explicitly NOT implemented yet (by design)

HTTP worker tools (Part 3: `http.*` remain registered-but-unimplemented;
workers honestly report NEEDS_TOOL), browser automation (Part 4),
knowledge retrieval (Part 5), reporting (Part 6+), vulnerability-specific
workers. Registered interfaces return clear `NOT_IMPLEMENTED` errors; the
UI marks them honestly.

## Quick start

```bash
npm install
cp .env.example .env
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
| `npm run test` | all 297 tests (starts DB automatically) |
| `npm run test:unit / :integration / :security / :e2e` | individual suites |
| `npx tsx scripts/smoke.ts` | 28-check end-to-end smoke test |
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
