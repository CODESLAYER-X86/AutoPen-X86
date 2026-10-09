/**
 * @aegis/hardening — Part 8 production hardening engine.
 *
 * Composes the deterministic security/reliability/operations controls:
 * trust tagging, zero-trust internal auth, API credentials, scoped
 * credential grants, artifact safety, circuit breakers, security events,
 * the emergency stop, scope versioning, the transactional outbox,
 * retention, health/readiness and the tamper-evident audit chain.
 */
import type { Pool } from 'pg';
import type { Repositories } from '@aegis/database';
import { AuditRepository } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import { CircuitBreakerEngine } from './security/circuit-breakers.js';
import { EmergencyStopEngine } from './security/emergency-stop.js';
import { SecurityEventsEngine } from './security/security-events.js';
import { CredentialsEngine, type SecretProvider } from './credentials/credentials.js';
import { ScopeVersionsEngine } from './ops/scope-versions.js';
import { HealthEngine, OutboxEngine, RetentionEngine, type DependencyProbe } from './ops/ops.js';

export {
  // Trust boundaries.
  tagTargetContent,
  tagExternalKnowledge,
  tagModelOutput,
  renderTagged,
  stripTrustEnvelopes,
} from './trust/trust.js';
export type { TaggedContent } from './trust/trust.js';

export {
  createInternalToken,
  verifyInternalToken,
  InternalAuthError,
} from './security/internal-auth.js';
export type { InternalTokenClaims, InternalSubject } from './security/internal-auth.js';

export {
  detectArtifactKind,
  evaluateArtifactSafety,
  normalizeArchiveEntryPath,
  assertResearchEgressAllowed,
  DEFAULT_ARTIFACT_LIMITS,
} from './security/artifact-safety.js';
export type { ArtifactSafetyLimits, ArtifactSafetyVerdict } from './security/artifact-safety.js';

export { SecurityEventsEngine, CATEGORY_SEVERITY_DEFAULTS } from './security/security-events.js';
export { CircuitBreakerEngine, BREAKER_THRESHOLDS } from './security/circuit-breakers.js';
export { EmergencyStopEngine, EmergencyStopError } from './security/emergency-stop.js';
export { CredentialsEngine, CredentialResolutionError } from './credentials/credentials.js';
export type { SecretProvider, SecretValue } from './credentials/credentials.js';
export { ScopeVersionsEngine, computeScopeDiff } from './ops/scope-versions.js';
export type { ScopeRulesShape, ScopeDiff } from './ops/scope-versions.js';
export { OutboxEngine, RetentionEngine, HealthEngine } from './ops/ops.js';
export type { DependencyProbe } from './ops/ops.js';

export interface HardeningEngineDeps {
  repos: Repositories;
  pool: Pool;
  secretStore: SecretProvider;
  eventBus?: { publish(event: PlatformEvent): Promise<void> };
  dependencyProbes?: DependencyProbe[];
}

export class HardeningEngine {
  readonly securityEvents: SecurityEventsEngine;
  readonly circuitBreakers: CircuitBreakerEngine;
  readonly emergencyStop: EmergencyStopEngine;
  readonly credentials: CredentialsEngine;
  readonly scopeVersions: ScopeVersionsEngine;
  readonly outbox: OutboxEngine;
  readonly retention: RetentionEngine;
  readonly health: HealthEngine;
  readonly audit: AuditRepository;

  constructor(deps: HardeningEngineDeps) {
    const eventPort = deps.eventBus;
    this.securityEvents = new SecurityEventsEngine({ repos: deps.repos, eventBus: eventPort });
    this.circuitBreakers = new CircuitBreakerEngine({ repos: deps.repos, eventBus: eventPort });
    this.emergencyStop = new EmergencyStopEngine({
      repos: {
        emergencyStop: deps.repos.emergencyStop,
        tasks: deps.repos.tasks,
        credentialGrants: deps.repos.credentialGrants,
      },
      eventBus: eventPort,
    });
    this.credentials = new CredentialsEngine({
      repos: {
        apiCredentials: deps.repos.apiCredentials,
        credentialGrants: deps.repos.credentialGrants,
        securityEvents: deps.repos.securityEvents,
        audit: deps.repos.audit,
      },
      secretStore: deps.secretStore,
      eventBus: eventPort,
    });
    this.scopeVersions = new ScopeVersionsEngine({
      repos: { scopeVersions: deps.repos.scopeVersions, audit: deps.repos.audit },
      eventBus: eventPort,
    });
    const opsDeps = {
      repos: {
        outbox: deps.repos.outbox,
        retentionPolicies: deps.repos.retentionPolicies,
        events: deps.repos.events,
        httpResponses: deps.repos.httpResponses,
      },
      eventBus: eventPort,
    };
    this.outbox = new OutboxEngine(opsDeps);
    this.retention = new RetentionEngine(opsDeps);
    this.health = new HealthEngine(
      { dbLatencyProbe: async () => true },
      deps.dependencyProbes ?? [
        {
          name: 'postgresql',
          probe: async () => {
            try {
              await deps.pool.query('SELECT 1');
              return true;
            } catch {
              return false;
            }
          },
        },
      ],
    );
    this.audit = deps.repos.audit;
  }

  /** Startup housekeeping: backfill the audit hash chain lazily (§85). */
  async startup(): Promise<{ chainBackfilled: number }> {
    const chainBackfilled = await this.audit.backfillChainHashes();
    return { chainBackfilled };
  }

  /** Tamper-evidence check used by operators + the readiness test (§111). */
  verifyAuditChain() {
    return this.audit.verifyChain();
  }
}
