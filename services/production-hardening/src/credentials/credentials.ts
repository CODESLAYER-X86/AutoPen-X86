/**
 * Credential governance (spec Part 8 §12-§15, §93).
 *
 * The SecretProvider abstraction centralizes secret access; workers never
 * touch the store directly. Credential resolution for a worker goes through
 * a GRANT: the grant binds (engagement, identity, target, purpose, expiry)
 * and resolution fails closed when any dimension does not match. Revocation
 * is immediate and audited (§93 kill switch).
 */
import type { ApiCredentialRecord, CredentialGrantRecord } from '@aegis/database';
import type { EventPort } from '../ops/ports.js';

export interface SecretValue {
  reference: string;
  value: string;
}

export interface SecretProvider {
  getSecret(reference: string): Promise<SecretValue>;
  rotate(reference: string): Promise<void>;
}

export interface CredentialsDeps {
  repos: {
    apiCredentials: {
      create(input: {
        userId: string;
        kind: 'API_KEY' | 'PERSONAL_ACCESS_TOKEN';
        name: string;
        scopes: string[];
        ttlHours: number;
      }): Promise<{ record: ApiCredentialRecord; token: string; tokenHash: string }>;
      listByUser(userId: string): Promise<ApiCredentialRecord[]>;
      revoke(id: string, userId: string): Promise<boolean>;
      expireStale(): Promise<number>;
    };
    credentialGrants: {
      create(input: {
        engagementId: string;
        identityId: string;
        targetId: string;
        secretReference: string;
        purpose: CredentialGrantRecord['purpose'];
        ttlMinutes: number;
      }): Promise<CredentialGrantRecord>;
      resolveForWorker(input: {
        engagementId: string;
        identityId: string;
        targetId: string;
        purpose: CredentialGrantRecord['purpose'];
      }): Promise<CredentialGrantRecord | null>;
      listByEngagement(engagementId: string): Promise<CredentialGrantRecord[]>;
      revoke(id: string): Promise<boolean>;
      revokeAllForEngagement(engagementId: string): Promise<number>;
      expireStale(): Promise<number>;
    };
    securityEvents: {
      create(input: {
        severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
        category: string;
        actor: 'AGENT' | 'MODEL' | 'WORKER' | 'USER' | 'PLATFORM';
        engagementId?: string | null;
        description: string;
        metadata?: Record<string, unknown>;
      }): Promise<unknown>;
    };
    audit: {
      create(input: {
        actorUserId: string | null;
        action: string;
        resource: string;
        resourceId?: string | null;
        engagementId?: string | null;
        metadata?: Record<string, unknown>;
      }): Promise<unknown>;
    };
  };
  secretStore: SecretProvider;
  eventBus?: EventPort;
}

export class CredentialResolutionError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'NO_GRANT'
      | 'GRANT_MISMATCH'
      | 'GRANT_EXPIRED'
      | 'SECRET_UNAVAILABLE'
      | 'INVALID_REQUEST',
  ) {
    super(message);
    this.name = 'CredentialResolutionError';
  }
}

export class CredentialsEngine {
  constructor(private readonly deps: CredentialsDeps) {}

  // -------------------------------------------------------------------------
  // API credentials (§11)
  // -------------------------------------------------------------------------

  async createApiCredential(input: {
    userId: string;
    kind: 'API_KEY' | 'PERSONAL_ACCESS_TOKEN';
    name: string;
    scopes: string[];
    ttlHours: number;
  }): Promise<{ record: ApiCredentialRecord; token: string }> {
    const created = await this.deps.repos.apiCredentials.create(input);
    await this.deps.repos.audit.create({
      actorUserId: input.userId,
      action: 'api_credential.created',
      resource: 'api_credential',
      resourceId: created.record.id,
      metadata: { kind: input.kind, scopes: input.scopes, ttl_hours: input.ttlHours },
    });
    await this.deps.eventBus?.publish({
      type: 'API_CREDENTIAL_CREATED',
      engagement_id: null,
      trace_id: created.record.id,
      actor_id: input.userId,
      payload: { kind: input.kind, scopes: input.scopes },
      occurred_at: new Date().toISOString(),
    });
    return { record: created.record, token: created.token };
  }

  async listApiCredentials(userId: string): Promise<ApiCredentialRecord[]> {
    return this.deps.repos.apiCredentials.listByUser(userId);
  }

  async revokeApiCredential(input: { id: string; userId: string }): Promise<boolean> {
    const revoked = await this.deps.repos.apiCredentials.revoke(input.id, input.userId);
    if (revoked) {
      await this.deps.repos.audit.create({
        actorUserId: input.userId,
        action: 'api_credential.revoked',
        resource: 'api_credential',
        resourceId: input.id,
        metadata: {},
      });
    }
    return revoked;
  }

  // -------------------------------------------------------------------------
  // Scoped grants (§14-§15)
  // -------------------------------------------------------------------------

  async issueGrant(input: {
    engagementId: string;
    identityId: string;
    targetId: string;
    secretReference: string;
    purpose: CredentialGrantRecord['purpose'];
    ttlMinutes: number;
    actorUserId: string;
  }): Promise<CredentialGrantRecord> {
    const grant = await this.deps.repos.credentialGrants.create({
      engagementId: input.engagementId,
      identityId: input.identityId,
      targetId: input.targetId,
      secretReference: input.secretReference,
      purpose: input.purpose,
      ttlMinutes: input.ttlMinutes,
    });
    await this.deps.repos.audit.create({
      actorUserId: input.actorUserId,
      action: 'credential_grant.issued',
      resource: 'credential_grant',
      resourceId: grant.id,
      engagementId: input.engagementId,
      metadata: { identity_id: input.identityId, target_id: input.targetId, purpose: input.purpose, ttl_minutes: input.ttlMinutes },
    });
    await this.deps.eventBus?.publish({
      type: 'CREDENTIAL_GRANT_ISSUED',
      engagement_id: input.engagementId,
      trace_id: grant.id,
      actor_id: input.actorUserId,
      payload: { identity_id: input.identityId, purpose: input.purpose },
      occurred_at: new Date().toISOString(),
    });
    return grant;
  }

  /**
   * The ONLY path a worker may use to obtain a secret. Full context match
   * (§15); every resolution is recorded as a CREDENTIAL_ACCESS security
   * event for the metrics layer (§49).
   */
  async resolveForWorker(input: {
    engagementId: string;
    identityId: string;
    targetId: string;
    purpose: CredentialGrantRecord['purpose'];
  }): Promise<SecretValue> {
    if (!input.engagementId || !input.identityId || !input.targetId) {
      throw new CredentialResolutionError(
        'Credential request must specify engagement, identity and target',
        'INVALID_REQUEST',
      );
    }
    const grant = await this.deps.repos.credentialGrants.resolveForWorker(input);
    if (!grant) {
      // Fail closed + observable: a worker probing for credentials raises a
      // CREDENTIAL_REQUEST breaker violation upstream (§98).
      await this.deps.repos.securityEvents.create({
        severity: 'HIGH',
        category: 'CREDENTIAL_ACCESS',
        actor: 'WORKER',
        engagementId: input.engagementId,
        description: 'Worker credential resolution failed: no matching active grant (fail-closed)',
        metadata: { identity_id: input.identityId, target_id: input.targetId, purpose: input.purpose },
      });
      throw new CredentialResolutionError(
        'No active credential grant matches the request context (engagement/identity/target/purpose)',
        'NO_GRANT',
      );
    }
    let secret: SecretValue;
    try {
      secret = await this.deps.secretStore.getSecret(grant.secret_reference);
    } catch (error) {
      throw new CredentialResolutionError(
        `Secret '${grant.secret_reference}' could not be resolved: ${(error as Error).message}`,
        'SECRET_UNAVAILABLE',
      );
    }
    await this.deps.repos.securityEvents.create({
      severity: 'INFO',
      category: 'CREDENTIAL_ACCESS',
      actor: 'WORKER',
      engagementId: input.engagementId,
      description: 'Worker resolved a scoped credential through a matching grant',
      metadata: { grant_id: grant.id, identity_id: input.identityId, purpose: input.purpose },
    });
    return secret;
  }

  /** Credential kill switch (§93): revoke one grant immediately. */
  async revokeGrant(input: { id: string; engagementId: string; actorUserId: string | null; reason: string }): Promise<boolean> {
    const revoked = await this.deps.repos.credentialGrants.revoke(input.id);
    if (revoked) {
      await this.deps.repos.securityEvents.create({
        severity: 'HIGH',
        category: 'CREDENTIAL_REVOKED',
        actor: 'USER',
        engagementId: input.engagementId,
        description: `Credential grant revoked: ${input.reason}`,
        metadata: { grant_id: input.id },
      });
      await this.deps.repos.audit.create({
        actorUserId: input.actorUserId,
        action: 'credential_grant.revoked',
        resource: 'credential_grant',
        resourceId: input.id,
        engagementId: input.engagementId,
        metadata: { reason: input.reason },
      });
      await this.deps.eventBus?.publish({
        type: 'CREDENTIAL_REVOKED',
        engagement_id: input.engagementId,
        trace_id: input.id,
        actor_id: input.actorUserId,
        payload: { reason: input.reason },
        occurred_at: new Date().toISOString(),
      });
    }
    return revoked;
  }

  /** Engagement kill switch support (§90): revoke all grants. */
  async revokeAllForEngagement(input: { engagementId: string; actorUserId: string | null; reason: string }): Promise<number> {
    const count = await this.deps.repos.credentialGrants.revokeAllForEngagement(input.engagementId);
    if (count > 0) {
      await this.deps.repos.audit.create({
        actorUserId: input.actorUserId,
        action: 'credential_grants.revoked_all',
        resource: 'engagement',
        resourceId: input.engagementId,
        engagementId: input.engagementId,
        metadata: { reason: input.reason, revoked: count },
      });
    }
    return count;
  }

  listGrants(engagementId: string): Promise<CredentialGrantRecord[]> {
    return this.deps.repos.credentialGrants.listByEngagement(engagementId);
  }

  /** Housekeeping: expire stale API credentials + grants. */
  async expireStale(): Promise<{ apiCredentials: number; grants: number }> {
    const [apiCredentials, grants] = await Promise.all([
      this.deps.repos.apiCredentials.expireStale(),
      this.deps.repos.credentialGrants.expireStale(),
    ]);
    return { apiCredentials, grants };
  }
}
