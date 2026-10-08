# Security Boundaries

## The hierarchy (spec §40)

```
USER -> ORCHESTRATOR -> MODEL -> STRUCTURED DECISION
     -> POLICY / SCOPE VALIDATION -> TOOL -> TARGET
     -> OBSERVATION -> DATABASE / EVIDENCE -> ORCHESTRATOR
```

Hard rules enforced by code, not convention:

1. **MODEL never touches TARGET** — model output is only ever a structured
   decision (zod-validated, `@aegis/contracts` `AgentDecisionSchema`) that a
   deterministic executor interprets.
2. **MODEL never touches DATABASE** — only repositories in `@aegis/database`
   write state; the model never sees a connection.
3. **MODEL never touches SHELL** — there is no shell tool. The registry
   rejects any unregistered tool name with `TOOL_NOT_FOUND` (hallucinated
   tool names die at the gate).
4. **TARGET never instructs MODEL** — target-controlled text (HTML, headers,
   responses, CTF descriptions) is stored as data/evidence; it is never
   concatenated into prompts as instructions. Part 2 will formalise the
   prompt-isolation rules on top of this invariant.

## Enforcement points

### 1. Scope checker (`packages/security/src/scope.ts`)

Pure, deterministic, exhaustively unit-tested. Evaluation order is fixed:
parse -> reject userinfo -> scheme allowlist -> excluded hosts (deny wins) ->
host/domain allowlist -> port allowlist -> excluded path prefixes.
Deny-wins ordering means an exclusion always overrides an allowance.

Applied at:
* target insertion (`/api/engagements/:id/targets`) — out-of-scope targets
  never reach the database and are audited as `TARGET_REJECTED`;
* every NETWORK-capability tool invocation via the ToolGateway URL check.

The LLM cannot bypass scope — it is not consulted.

### 2. Tool gateway (`packages/tools/src/gateway.ts`)

The only path from any decision to execution. Pipeline: registry lookup ->
implemented check -> input schema validation -> capability gates (NETWORK
permission + scope, BROWSER permission, DESTRUCTIVE engagement permission,
AUTHENTICATED identity) -> URL scope check -> timeout -> output schema
validation. Structured failure results; nothing executes partially.

### 3. State machine (`services/orchestrator/src/state-machine.ts`)

Engagement transitions are a frozen map; invalid transitions throw typed
errors regardless of who asks. `DRAFT -> READY` requires a scope AND at least
one in-scope target (readiness evaluation).

### 4. Authentication & authorization

* Opaque 256-bit bearer tokens; only SHA-256 hashes are stored.
* Scrypt password hashing (no native modules).
* Cross-tenant access returns **404, not 403** to avoid resource-existence
  leaks (documented trade-off; both are denials).
* Rate limiting: separate strict bucket for auth endpoints, general bucket
  for the API. 429 typed errors.

### 5. Secrets

* Credential material lives in an AES-256-GCM encrypted file store
  (`packages/security/src/secret-store.ts`); the database holds only
  `SEC_…` references.
* The Google API key is read directly from the environment by the provider;
  the config object carries only `googleApiKeyConfigured: boolean`.
* All log metadata passes the redaction engine (sensitive keys at any depth,
  Bearer/JWT/common-key patterns scrubbed in free-form strings).
* Tests assert secrets never appear in logs, DB rows, or API responses.

### 6. Input hardening

* Every API body is validated against strict zod schemas (unknown fields
  rejected).
* Body size limit from config (default 1 MiB) -> 413.
* Error responses never include stack traces or server-side details; details
  are exposed only for 4xx validation errors.
* Security headers on every response (nosniff, DENY, CSP `default-src 'none'`,
  no-store, no-referrer).

## What is deliberately NOT implemented

The autonomous run loop, HTTP worker, browser worker, knowledge retrieval and
reporting are registered interfaces only. Calling them yields explicit
`NotImplementedError` (HTTP 501 semantics) — the UI marks them as
"not implemented in Part 1". No placeholder pretends to work.
