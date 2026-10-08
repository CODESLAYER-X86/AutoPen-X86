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
