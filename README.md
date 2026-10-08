# Aegis Platform

Autonomous web-security testing and CTF-solving platform.
**Part 1 of 8: foundation, repository, runtime, data model, security
boundaries and core contracts — implemented, built and tested.**

> **Authorized use only.** This platform is built for authorized penetration
> testing, local security laboratories, intentionally vulnerable
> applications and CTF environments. Every engagement requires an explicit,
> deterministic scope; nothing outside that scope can be contacted by any
> tool, worker, or model decision.

## What Part 1 includes (real, runnable)

- **Monorepo** (npm workspaces, TypeScript ESM): Fastify API, React+Vite UI,
  10 packages, 6 services, 12 hash-verified SQL migrations
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
- **Abstractions ready for Parts 2–8** — tool registry + permission/scope
  gateway (1 real tool: `parser.jwt`), model provider interface (mock +
  Google REST), event bus, job queue, orchestrator, worker interfaces
- **202 automated tests** (unit / integration / security / e2e) + a
  20-check smoke test, all green

## What is explicitly NOT implemented yet (by design)

Autonomous run loop (Part 2), HTTP worker (Part 3), browser worker (Part 4),
knowledge retrieval (Part 5), reporting (Part 6+). Registered interfaces
return clear `NOT_IMPLEMENTED` errors; the UI marks them honestly.

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
add target (out-of-scope targets are rejected) → start.

## Commands

| Command | Purpose |
|---|---|
| `npm run typecheck` / `lint` / `build` | quality gates |
| `npm run test` | all 202 tests (starts DB automatically) |
| `npm run test:unit / :integration / :security / :e2e` | individual suites |
| `npx tsx scripts/smoke.ts` | 20-check end-to-end smoke test |
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
