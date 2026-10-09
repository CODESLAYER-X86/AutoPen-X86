# Incident Response Runbook (Part 8 §94-§96)

## Severity ladder (§95)

| Severity | Meaning | Example |
| --- | --- | --- |
| LOW | contained anomaly | prompt injection encountered and neutralised |
| MEDIUM | degraded reliability | repeated malformed model decisions |
| HIGH | boundary attempt | out-of-scope tool execution blocked |
| CRITICAL | confirmed breach | credential exposure, cross-tenant data exposure, worker escape |

The platform auto-raises security events at control points (scope gateway,
credential resolution, tool gateway). HIGH/CRITICAL events inside a 30-minute
window auto-open an incident (`incidents` table) with the events attached —
the timeline (events → actors → affected resources → actions) is reconstructable
from `security_events` alone.

## Procedure per scenario

1. **Credential leak (§93)** — revoke: `POST /api/engagements/:id/grants/:gid/revoke`
   or the platform kill switch `POST /api/security/emergency-stop/engage`. If a
   platform API key leaked: `POST /api/api-keys/:id/revoke`. Rotate secrets
   (credential-rotation.md). Audit + notify per policy.
2. **Scope violation** — the scope gateway already denied it; check
   `/api/metrics` `scope_denials` and the incident; the agent circuit breaker
   pauses the engagement after repeated violations (§98).
3. **Worker compromise (§72)** — engage the emergency stop; workers are
   capability-scoped and credential-granted, so blast radius is one engagement;
   rotate the internal service token secret and redeploy.
4. **Database compromise** — restore per backup-restore.md; the audit hash
   chain detects record tampering (`POST /api/audit-chain/verify`).
5. **Malicious target content** — content is untrusted by construction
   (§35-§36); injection events appear as LOW/MEDIUM. Investigate via the event
   metadata; no policy change is possible from content.
6. **Unexpected outbound network** — egress guards + scope gateway deny by
   default; each denial is a security event with the destination in metadata.

## After the incident

Update the incident status through OPEN → INVESTIGATING → MITIGATED → RESOLVED.
Every confirmed platform vulnerability becomes a regression test in
`tests/security/` (§113).
