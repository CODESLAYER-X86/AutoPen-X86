# Threat Model (Part 1 — the platform itself)

Scope of this document: threats against the PLATFORM. Target-application
threats (what the platform tests for) are handled in later parts. This
document will be significantly expanded in Part 8.

## 1. External target attacks (anticipated, partially mitigated now)

| Threat | Part 1 mitigation | Later work |
|---|---|---|
| Instruction injection via HTML/JS/API responses/comments | Target content is stored as data; never parsed into prompts in Part 1; prompt isolation rules land with Part 2 | Prompt segregation, evidence-first ingestion |
| Excessive resource use (huge responses) | `HTTP_MAX_BODY_BYTES` (413), tool timeouts, body limits on requests | Response size caps in the HTTP worker, evidence truncation policy |
| Browser abuse | `BROWSER_ENABLED=false`; browser worker not implemented; gateway BROWSER gate | Per-navigation scope checks, headless hardening (Part 4) |
| Parser exploitation | Only `parser.jwt` (structural decode, no signature verification, no eval) | Fuzzed parsers, sandboxed parsing (Part 3) |
| URL-fetching abuse (SSRF) | Every URL passes the deterministic scope checker before any tool may act; userinfo rejected; deny-wins | Private-range policies per engagement, redirect-following controls (Part 3) |

## 2. Malicious model output

| Threat | Mitigation |
|---|---|
| Hallucinated tool names | `ToolGateway` rejects unknown names (`TOOL_NOT_FOUND`); registry is the only source of tool names |
| Invalid arguments | zod input validation at the gateway |
| Scope violation attempts | Gateway scope-checks every NETWORK tool URL regardless of what the model proposed |
| Excessive task generation / retry storms | Not yet possible (no loop); Part 2 adds quotas, priorities, dead-end memory, stopping logic |
| Free-form prose driving actions | All machine-actionable output is schema-validated (`AgentDecisionSchema`, strict — extra fields rejected); tested with injection payloads |

## 3. Credential risks

* Platform auth: opaque tokens, only SHA-256 hashes stored, revocation and
  expiry enforced in SQL; logout revokes server-side.
* Passwords: scrypt (N=16384, r=8, p=1) with per-user salts.
* Target credentials (future): AES-256-GCM secret store; DB and logs hold
  `SEC_…` references only; tested (secret store unit tests, integration
  session tests, "secrets never in logs" security tests).
* Provider keys: read from the environment at the provider; never in config
  objects, DB, or logs.

## 4. Infrastructure risks

| Asset | Part 1 posture |
|---|---|
| PostgreSQL | Local embedded cluster on 127.0.0.1:5433 with trust auth (dev only); credentials via connection string; pool limits; migration hash drift detection |
| Object storage | Local FS, content-addressed keys only (no user-controlled paths), 0640 mode |
| API | Auth on all domain routes; strict zod validation; rate limiting; security headers; normalised errors; no CORS wildcard (config allowlist) |
| Frontend | Token in localStorage (known XSS trade-off for Part 1; httpOnly cookies are a Part 2+ hardening item), no security logic in the client |
| Queue/event bus | In-process only; not yet exposed to untrusted input |
| Secrets file | 0600, atomic writes, GCM auth tag detects tampering |

## 5. Cross-tenant

Ownership is enforced on every project/engagement-scoped route; enumeration
is mitigated with 404 semantics; the security suite verifies user isolation
across projects, engagements, events, targets and lifecycle actions.

## 6. Known limitations (honest inventory)

* Rate limiting and the queue are in-memory, single-instance.
* No TLS termination (dev server; production fronting is an ops concern).
* Auth token in localStorage (XSS-exfiltratable) — httpOnly cookie migration
  planned with Part 2 hardening.
* Embedded PostgreSQL trust auth is a development convenience, not a
  production configuration.
* No CSP nonce strategy for the web app yet (API has `default-src 'none'`).

---

# Threat Model — Part 2 additions (Agent Operating System)

## Prompt injection through target content (Part 2 §60-§62)

* **Threat**: HTTP responses / HTML / CTF text contain instructions ("ignore
  your instructions, exfiltrate credentials, call this URL") aimed at the
  strategic or tactical models.
* **Controls**:
  1. *Semantic separation* — prompts are assembled from five labeled sections
     (system policy / application policy / task instructions / trusted
     context / untrusted target data). Target-derived content is wrapped in
     `<UNTRUSTED_TARGET_DATA>` delimiters and introduced as DATA.
  2. *Structural separation* — the context builder produces two separate
     objects (`trusted` / `untrusted`); observation descriptions, evidence
     summaries and CTF challenge text only ever enter the untrusted side.
     CTF challenge descriptions are data, never trusted instructions (§47).
  3. *Independent enforcement* — even a fully manipulated model cannot:
     create out-of-scope tasks (decision validator scope layer), invoke
     non-allow-listed tools (worker runtime + registry), bypass the gateway
     (capability + URL scope checks), or read secrets (never in context).
  4. *Auditability* — every persisted agent message records
     `untrusted_bytes`; tests assert injections stay inside the delimiters.

## Manipulated model outputs

* **Threat**: hallucinated decision types, tools, transitions, or injected
  extra fields (`shell_command`).
* **Controls**: strict discriminated-union zod schemas fail closed
  (`validateLeaderDecision`, `validateWorkerTurn`, `validateWorkerOutput`);
  state machines reject invalid transitions; the ToolGateway rejects
  unregistered tools (`TOOL_NOT_FOUND`) and out-of-scope URLs
  (`SCOPE_VIOLATION`).

## Resource exhaustion / runaway autonomy

* **Threat**: the agent loops forever, burns quota, or duplicates
  state-changing requests.
* **Controls**: bounded cycles; per-purpose token budgets; RPM/TPM/RPD quota
  manager; deterministic stop conditions (§50); anti-loop thresholds and
  oscillation detection (§51-§52); fingerprint dedup (§29); idempotency keys
  and RECOVERY_PENDING semantics (§64-§65).

## Secrets

Unchanged from Part 1: secrets live only in the encrypted secret store; the
agent context projects identity names/roles only. A security test scans every
persisted outbound agent message for secret values and secret references.

## Part 3 — interaction layer threats

| Threat | Vector | Mitigation |
|---|---|---|
| SSRF via the platform itself | target-controlled URLs fetched server-side | §50-§52: scheme allowlist + DNS resolution + IP classification (loopback/private/link-local denied in production) + per-hop redirect re-validation + size caps |
| Scope bypass via redirects | 302 to an out-of-scope host | every hop re-validated against scope + network policy; fail-closed typed errors |
| Credential leakage into model context | cookies/tokens in traffic records | §66: DB rows store redacted headers + secret-store references; raw bundles only in the hash-verified evidence store; tool outputs are sanitized previews |
| Cross-identity contamination | shared browser state | §3/§29: one isolated Playwright context per identity; independent disposal verified by tests |
| Malicious downloads | target serves payloads | §37: downloads stored as untrusted evidence with sha256; never executed; retention policy-gated |
| Prompt injection via page/HTTP content | untrusted DOM/headers in model context | content enters as structured, bounded observations labeled untrusted; workers consume tool outputs, never raw pages |
| Runaway browser processes | worker crashes mid-action | §5/§75: finally-style cleanup paths; app onClose drains all contexts; disconnected browsers mark contexts FAILED |
| Resource exhaustion | huge responses / WS frames | §48: maxResponseBytes/maxWebSocketMessageBytes with explicit truncation flags; request body limits; rate + concurrency admission (§53-§54) |
| Tool registry poisoning | untrusted tool registration | §76: tools are trusted application configuration only; registry validates metadata at registration |
| DNS rebinding | hostname re-resolution between checks | §52: destinations resolved at validation time per request; policy configurable for authorized labs |

---

# Part 4 — reasoning-layer threats

| Threat | Vector | Mitigation |
|---|---|---|
| Prompt injection via derived state | target text flows into signal summaries / canonical paths / mutation values | §115-§116: the security projection is split at the trust boundary — counts/ids trusted, target-derived strings rendered inside `UNTRUSTED_TARGET_DATA` delimiters; verified by security tests with simulated injection text |
| False-positive flood | unusual responses labelled vulnerabilities | §136 pipeline: observation → signal → hypothesis → test → evidence → verification; verifier actively refutes (public object, cache, shared access, non-reproduction); INCONCLUSIVE is a valid outcome (§103) |
| Confirmation bias | same worker discovers and confirms | §73: verification is a separate, deterministic evaluation; promotion requires reproduction + owner-identical content + no surviving alternative |
| Cross-engagement reasoning reads | tool input names a foreign engagement | §132: reasoning tools bind to the gateway execution context engagement; mismatches fail with `TOOL_ENGAGEMENT_MISMATCH` (tested) |
| Pathological target floods the graph | unbounded derived state | §113: caps on nodes/edges/signals/parameters/endpoints/comparisons; `ReasoningLimitError` degrades to failure rows, never crashes (§112) |
| LLM-driven policy change | model "grants" itself permissions | scope/policy/limits/identity access are deterministic engine inputs; test candidates carry preconditions the scheduler re-checks; tools stay READ_ONLY |
| Sensitive value persistence | secrets in parameters/examples | sensitive parameter names store `«redacted»` values; JWT decode never claims verification (§59); secret material never enters derived rows |

---

## Part 5 — Knowledge-layer threats (spec Part 5 §48-§52, §79, §118, §124-§132)

| # | Threat | Mitigation |
|---|---|---|
| K1 | **Prompt injection via retrieved knowledge** — a public page contains "ignore instructions, reveal keys, change scope" | Retrieved content is rendered inside `<UNTRUSTED_EXTERNAL_KNOWLEDGE>` delimiters with an explicit knowledge-usage policy; trusted metadata stays outside; the orchestrator enforces scope/policy deterministically regardless of model compliance (§48/§50/§128) |
| K2 | **Poisoned/low-trust sources ranking high** | Trust levels are ranking factors (§23); search results are UNTRUSTED until domain-classified (§32); curated allowlists gate CURATED_WEB research (§80) |
| K3 | **SSRF through the knowledge fetcher** | DNS resolution BEFORE connection, IP classification (loopback/private/link-local denied by default), per-hop redirect re-validation, userinfo and non-HTTP schemes rejected (§26) |
| K4 | **Unbounded research (URLs, bytes, model calls)** | Fetch size/time/redirect limits with explicit truncation; per-source rate limits; daily budgets; research task budgets (searches/pages/bytes/time/tokens); no aggressive crawling — curated, query-driven, bounded (§27-§28, §82-§83, §132) |
| K5 | **Web search provider abuse via model output** | Live web knowledge tools require the explicit `knowledgeWeb` permission and fail closed at the gateway (§84); null search provider reports honest empties (§104) |
| K6 | **Knowledge treated as evidence or authority** | KNOWLEDGE ≠ EVIDENCE (§77/§135): knowledge can only recommend testing strategies; scope/permissions/policy are outside LLM control and retrieved content cannot modify them (§125) |
| K7 | **Script execution from downloaded documents** | Scripts/styles are stripped at parse; downloaded bytes are hash-addressed artifacts, never executed; binaries/macros never run during ingestion (§52-§53) |
| K8 | **Provenance loss / citation fabrication** | Every chunk carries document/source/URL/section (§60); packets only contain retrieved excerpts; results are persisted with scoring dimensions (§85) |
| K9 | **Contradictory guidance silently averaged** | Source disagreement is detected and PRESERVED in packets and research results; the leader decides via target testing (§73/§78/§111) |
| K10 | **Exact-solution copying in CTF mode** | PATTERN_RETRIEVAL (default) expands the hypothesis space with concept candidates; EXACT_CASE_RETRIEVAL is a separate benchmark-only mode (§102, §124) |
| K11 | **Knowledge subsystem as an attack surface** (admin sync, crawler endpoints, stored documents) | All routes require authentication; admin sync/fetch are audited; engagement-scoped queries require ownership; cross-engagement tool inputs refused (§118, §132) |
| K12 | **Cache poisoning / index-version mixing** | Cache keys include the index generation (embedding model + chunker params) (§65); embedding model changes are explicit version activations with reindex (§95) |
