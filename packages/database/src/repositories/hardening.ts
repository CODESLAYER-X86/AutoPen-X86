/**
 * Part 8 repositories — production hardening state (spec Part 8 §11, §15,
 * §44, §59, §89, §91-§99).
 *
 * All writes are engagement-scoped or user-scoped; security events and the
 * emergency stop are platform-level. Credential grants resolve ONLY through
 * resolveForWorker() which enforces the full context match (§15).
 */
import { createHash, randomBytes } from 'node:crypto';
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  ApiCredentialRecord,
  BackupRecordRecord,
  CircuitBreakerRecord,
  CredentialGrantRecord,
  EmergencyStopRecord,
  IncidentRecord,
  OutboxEventRecord,
  RetentionPolicyRecord,
  ScopeVersionRecord,
  SecurityEventRecord,
} from '../types.js';
import { requireIso, type RepoBase } from './util.js';

// ---------------------------------------------------------------------------
// API credentials (§11)
// ---------------------------------------------------------------------------

export class ApiCredentialsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: {
    userId: string;
    kind: 'API_KEY' | 'PERSONAL_ACCESS_TOKEN';
    name: string;
    scopes: string[];
    ttlHours: number;
  }): Promise<{ record: ApiCredentialRecord; token: string; tokenHash: string }> {
    const id = generateId('AKC');
    // aegis_<random url-safe secret>; only the SHA-256 hash is persisted.
    const token = `aegis_${randomBytes(24).toString('base64url')}`;
    const tokenHash = hashToken(token);
    const result = await this.pool.query(
      `INSERT INTO api_credentials (id, user_id, kind, name, token_hash, scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + ($7 || ' hours')::interval)
       RETURNING id, user_id, kind, name, token_hash, scopes, status, created_at, expires_at, last_used_at, revoked_at`,
      [id, input.userId, input.kind, input.name, tokenHash, input.scopes, String(input.ttlHours)],
    );
    return { record: mapApiCredential(result.rows[0]!), token, tokenHash };
  }

  async findActiveByTokenHash(tokenHash: string): Promise<ApiCredentialRecord | null> {
    const result = await this.pool.query(
      `SELECT id, user_id, kind, name, token_hash, scopes, status, created_at, expires_at, last_used_at, revoked_at
       FROM api_credentials
       WHERE token_hash = $1 AND status = 'ACTIVE' AND expires_at > now()`,
      [tokenHash],
    );
    return result.rows[0] ? mapApiCredential(result.rows[0]) : null;
  }

  async touchLastUsed(id: string): Promise<void> {
    await this.pool.query('UPDATE api_credentials SET last_used_at = now() WHERE id = $1', [id]);
  }

  async listByUser(userId: string): Promise<ApiCredentialRecord[]> {
    const result = await this.pool.query(
      `SELECT id, user_id, kind, name, token_hash, scopes, status, created_at, expires_at, last_used_at, revoked_at
       FROM api_credentials WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return result.rows.map(mapApiCredential);
  }

  async revoke(id: string, userId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE api_credentials
         SET status = 'REVOKED', revoked_at = now()
       WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
      [id, userId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async expireStale(): Promise<number> {
    const result = await this.pool.query(
      `UPDATE api_credentials SET status = 'EXPIRED'
       WHERE status = 'ACTIVE' AND expires_at <= now()`,
    );
    return result.rowCount ?? 0;
  }
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Credential grants (§14-§15)
// ---------------------------------------------------------------------------

export class CredentialGrantsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: {
    engagementId: string;
    identityId: string;
    targetId: string;
    secretReference: string;
    purpose: 'AUTHENTICATION' | 'VERIFICATION' | 'REPRODUCTION';
    ttlMinutes: number;
  }): Promise<CredentialGrantRecord> {
    const id = generateId('CGR');
    const result = await this.pool.query(
      `INSERT INTO credential_grants (id, engagement_id, identity_id, target_id, secret_reference, purpose, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + ($7 || ' minutes')::interval)
       RETURNING id, engagement_id, identity_id, target_id, secret_reference, purpose, status,
                 created_at, expires_at, revoked_at, consumed_at`,
      [
        id,
        input.engagementId,
        input.identityId,
        input.targetId,
        input.secretReference,
        input.purpose,
        String(input.ttlMinutes),
      ],
    );
    return mapGrant(result.rows[0]!);
  }

  /**
   * The ONLY resolution path workers may use. Full context match required;
   * anything else returns null (fail-closed, spec §15).
   */
  async resolveForWorker(input: {
    engagementId: string;
    identityId: string;
    targetId: string;
    purpose: 'AUTHENTICATION' | 'VERIFICATION' | 'REPRODUCTION';
  }): Promise<CredentialGrantRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, identity_id, target_id, secret_reference, purpose, status,
              created_at, expires_at, revoked_at, consumed_at
       FROM credential_grants
       WHERE engagement_id = $1 AND identity_id = $2 AND target_id = $3 AND purpose = $4
         AND status = 'ISSUED' AND expires_at > now()
       ORDER BY created_at DESC LIMIT 1`,
      [input.engagementId, input.identityId, input.targetId, input.purpose],
    );
    return result.rows[0] ? mapGrant(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string): Promise<CredentialGrantRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, identity_id, target_id, secret_reference, purpose, status,
              created_at, expires_at, revoked_at, consumed_at
       FROM credential_grants WHERE engagement_id = $1 ORDER BY created_at DESC`,
      [engagementId],
    );
    return result.rows.map(mapGrant);
  }

  async revoke(id: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE credential_grants SET status = 'REVOKED', revoked_at = now()
       WHERE id = $1 AND status IN ('ISSUED', 'EXPIRED')`,
      [id],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async revokeAllForEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      `UPDATE credential_grants SET status = 'REVOKED', revoked_at = now()
       WHERE engagement_id = $1 AND status = 'ISSUED'`,
      [engagementId],
    );
    return result.rowCount ?? 0;
  }

  /** Emergency stop helper: revoke every issued grant platform-wide (§89). */
  async revokeAllIssued(): Promise<number> {
    const result = await this.pool.query(
      `UPDATE credential_grants SET status = 'REVOKED', revoked_at = now()
       WHERE status = 'ISSUED'`,
    );
    return result.rowCount ?? 0;
  }

  async expireStale(): Promise<number> {
    const result = await this.pool.query(
      `UPDATE credential_grants SET status = 'EXPIRED'
       WHERE status = 'ISSUED' AND expires_at <= now()`,
    );
    return result.rowCount ?? 0;
  }
}

// ---------------------------------------------------------------------------
// Scope versions (§91-§92)
// ---------------------------------------------------------------------------

export class ScopeVersionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async propose(input: {
    engagementId: string;
    scope: Record<string, unknown>;
    diff: Record<string, unknown>;
    createdBy: string;
  }): Promise<ScopeVersionRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const max = await client.query<{ max: string | null }>(
        'SELECT MAX(version) AS max FROM scope_versions WHERE engagement_id = $1',
        [input.engagementId],
      );
      const version = Number(max.rows[0]?.max ?? 0) + 1;
      const id = generateId('SCV');
      const result = await client.query(
        `INSERT INTO scope_versions (id, engagement_id, version, status, scope, diff, created_by)
         VALUES ($1, $2, $3, 'PROPOSED', $4::jsonb, $5::jsonb, $6)
         RETURNING id, engagement_id, version, status, scope, diff, created_by, created_at, activated_at`,
        [id, input.engagementId, version, JSON.stringify(input.scope), JSON.stringify(input.diff), input.createdBy],
      );
      await client.query('COMMIT');
      return mapScopeVersion(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /** Atomically supersede any active version and activate this one. */
  async activate(id: string): Promise<ScopeVersionRecord | null> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const current = await client.query<{ engagement_id: string }>(
        `SELECT engagement_id FROM scope_versions WHERE id = $1 AND status = 'PROPOSED'`,
        [id],
      );
      if (current.rows.length === 0) {
        await client.query('COMMIT');
        return null;
      }
      const engagementId = current.rows[0]!.engagement_id;
      await client.query(
        `UPDATE scope_versions SET status = 'SUPERSEDED' WHERE engagement_id = $1 AND status = 'ACTIVE'`,
        [engagementId],
      );
      const result = await client.query(
        `UPDATE scope_versions SET status = 'ACTIVE', activated_at = now()
         WHERE id = $1
         RETURNING id, engagement_id, version, status, scope, diff, created_by, created_at, activated_at`,
        [id],
      );
      await client.query('COMMIT');
      return mapScopeVersion(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async findActive(engagementId: string): Promise<ScopeVersionRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, version, status, scope, diff, created_by, created_at, activated_at
       FROM scope_versions WHERE engagement_id = $1 AND status = 'ACTIVE'`,
      [engagementId],
    );
    return result.rows[0] ? mapScopeVersion(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string): Promise<ScopeVersionRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, version, status, scope, diff, created_by, created_at, activated_at
       FROM scope_versions WHERE engagement_id = $1 ORDER BY version DESC`,
      [engagementId],
    );
    return result.rows.map(mapScopeVersion);
  }
}

// ---------------------------------------------------------------------------
// Security events + incidents (§94-§96)
// ---------------------------------------------------------------------------

export class SecurityEventsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: {
    severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    category: string;
    actor: 'AGENT' | 'MODEL' | 'WORKER' | 'USER' | 'PLATFORM';
    engagementId?: string | null;
    description: string;
    metadata?: Record<string, unknown>;
  }): Promise<SecurityEventRecord> {
    const id = generateId('SEV');
    const result = await this.pool.query(
      `INSERT INTO security_events (id, severity, category, actor, engagement_id, description, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id, incident_id, severity, category, actor, engagement_id, description, metadata, created_at`,
      [
        id,
        input.severity,
        input.category,
        input.actor,
        input.engagementId ?? null,
        input.description,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapSecurityEvent(result.rows[0]!);
  }

  async attachToIncident(ids: string[], incidentId: string): Promise<number> {
    if (ids.length === 0) return 0;
    const result = await this.pool.query(
      'UPDATE security_events SET incident_id = $1 WHERE id = ANY($2) AND incident_id IS NULL',
      [incidentId, ids],
    );
    return result.rowCount ?? 0;
  }

  async list(input: {
    severity?: string;
    engagementId?: string;
    limit: number;
  }): Promise<SecurityEventRecord[]> {
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (input.severity) {
      params.push(input.severity);
      conditions.push(`severity = $${params.length}`);
    }
    if (input.engagementId) {
      params.push(input.engagementId);
      conditions.push(`engagement_id = $${params.length}`);
    }
    params.push(Math.min(Math.max(input.limit, 1), 500));
    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const result = await this.pool.query(
      `SELECT id, incident_id, severity, category, actor, engagement_id, description, metadata, created_at
       FROM security_events ${where} ORDER BY created_at DESC LIMIT $${params.length}`,
      params,
    );
    return result.rows.map(mapSecurityEvent);
  }

  async countByCategorySince(category: string, sinceMinutes: number): Promise<number> {
    const result = await this.pool.query(
      `SELECT COUNT(*)::int AS count FROM security_events
       WHERE category = $1 AND created_at > now() - ($2 || ' minutes')::interval`,
      [category, String(sinceMinutes)],
    );
    return result.rows[0]?.count ?? 0;
  }

  async listUnlinkedSince(sinceMinutes: number, limit: number): Promise<SecurityEventRecord[]> {
    const result = await this.pool.query(
      `SELECT id, incident_id, severity, category, actor, engagement_id, description, metadata, created_at
       FROM security_events
       WHERE incident_id IS NULL AND severity IN ('HIGH', 'CRITICAL')
         AND created_at > now() - ($1 || ' minutes')::interval
       ORDER BY created_at DESC LIMIT $2`,
      [String(sinceMinutes), Math.min(Math.max(limit, 1), 100)],
    );
    return result.rows.map(mapSecurityEvent);
  }
}

export class IncidentsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async open(input: {
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    title: string;
    eventIds: string[];
  }): Promise<IncidentRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const id = generateId('INC');
      const result = await client.query(
        `INSERT INTO incidents (id, severity, title) VALUES ($1, $2, $3)
         RETURNING id, status, severity, title, opened_at, resolved_at`,
        [id, input.severity, input.title],
      );
      if (input.eventIds.length > 0) {
        await client.query(
          'UPDATE security_events SET incident_id = $1 WHERE id = ANY($2) AND incident_id IS NULL',
          [id, input.eventIds],
        );
      }
      await client.query('COMMIT');
      return { ...mapIncident(result.rows[0]!), event_count: input.eventIds.length };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async updateStatus(id: string, status: string): Promise<IncidentRecord | null> {
    const result = await this.pool.query(
      `UPDATE incidents
         SET status = $2, resolved_at = CASE WHEN $2 = 'RESOLVED' THEN now() ELSE resolved_at END
       WHERE id = $1
       RETURNING id, status, severity, title, opened_at, resolved_at`,
      [id, status],
    );
    if (result.rows.length === 0) return null;
    const count = await this.pool.query<{ count: number }>(
      'SELECT COUNT(*)::int AS count FROM security_events WHERE incident_id = $1',
      [id],
    );
    return { ...mapIncident(result.rows[0]!), event_count: count.rows[0]?.count ?? 0 };
  }

  async listOpen(): Promise<IncidentRecord[]> {
    const result = await this.pool.query(
      `SELECT i.id, i.status, i.severity, i.title, i.opened_at, i.resolved_at,
              (SELECT COUNT(*)::int FROM security_events se WHERE se.incident_id = i.id) AS event_count
       FROM incidents i WHERE i.status <> 'RESOLVED' ORDER BY i.opened_at DESC`,
    );
    return result.rows.map(mapIncident);
  }

  async findById(id: string): Promise<IncidentRecord | null> {
    const result = await this.pool.query(
      `SELECT i.id, i.status, i.severity, i.title, i.opened_at, i.resolved_at,
              (SELECT COUNT(*)::int FROM security_events se WHERE se.incident_id = i.id) AS event_count
       FROM incidents i WHERE i.id = $1`,
      [id],
    );
    return result.rows[0] ? mapIncident(result.rows[0]) : null;
  }
}

// ---------------------------------------------------------------------------
// Circuit breakers (§98-§99)
// ---------------------------------------------------------------------------

export class CircuitBreakersRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /**
   * Deterministic violation counter. When the threshold is reached the
   * breaker flips to OPEN atomically and stays open until a human reset.
   */
  async recordViolation(input: {
    subject: 'AGENT' | 'MODEL';
    subjectId: string;
    engagementId?: string | null;
    category: string;
    threshold: number;
  }): Promise<CircuitBreakerRecord> {
    const id = generateId('CBX');
    const result = await this.pool.query(
      `INSERT INTO circuit_breakers (id, subject, subject_id, engagement_id, category, state,
                                     violation_count, threshold)
       VALUES ($1, $2, $3, $4, $5, 'CLOSED', 1, $6)
       ON CONFLICT (subject, subject_id, category) DO UPDATE SET
         violation_count = circuit_breakers.violation_count + 1,
         updated_at = now()
       RETURNING id, subject, subject_id, engagement_id, category, state, violation_count,
                 threshold, tripped_at, reset_at, updated_at`,
      [id, input.subject, input.subjectId, input.engagementId ?? null, input.category, input.threshold],
    );
    const row = result.rows[0]!;
    if (row.state === 'CLOSED' && Number(row.violation_count) >= input.threshold) {
      const tripped = await this.pool.query(
        `UPDATE circuit_breakers SET state = 'OPEN', tripped_at = now(), updated_at = now()
         WHERE id = $1 AND state = 'CLOSED'
         RETURNING id, subject, subject_id, engagement_id, category, state, violation_count,
                   threshold, tripped_at, reset_at, updated_at`,
        [row.id],
      );
      return mapBreaker(tripped.rows[0]!);
    }
    return mapBreaker(row);
  }

  async reset(id: string): Promise<CircuitBreakerRecord | null> {
    const result = await this.pool.query(
      `UPDATE circuit_breakers
         SET state = 'CLOSED', violation_count = 0, reset_at = now(), updated_at = now()
       WHERE id = $1 AND state = 'OPEN'
       RETURNING id, subject, subject_id, engagement_id, category, state, violation_count,
                 threshold, tripped_at, reset_at, updated_at`,
      [id],
    );
    return result.rows[0] ? mapBreaker(result.rows[0]) : null;
  }

  async findOpen(subject: 'AGENT' | 'MODEL', subjectId: string): Promise<CircuitBreakerRecord[]> {
    const result = await this.pool.query(
      `SELECT id, subject, subject_id, engagement_id, category, state, violation_count,
              threshold, tripped_at, reset_at, updated_at
       FROM circuit_breakers
       WHERE subject = $1 AND subject_id = $2 AND state = 'OPEN'`,
      [subject, subjectId],
    );
    return result.rows.map(mapBreaker);
  }

  async listOpen(): Promise<CircuitBreakerRecord[]> {
    const result = await this.pool.query(
      `SELECT id, subject, subject_id, engagement_id, category, state, violation_count,
              threshold, tripped_at, reset_at, updated_at
       FROM circuit_breakers WHERE state = 'OPEN' ORDER BY tripped_at DESC`,
    );
    return result.rows.map(mapBreaker);
  }

  async listByEngagement(engagementId: string): Promise<CircuitBreakerRecord[]> {
    const result = await this.pool.query(
      `SELECT id, subject, subject_id, engagement_id, category, state, violation_count,
              threshold, tripped_at, reset_at, updated_at
       FROM circuit_breakers WHERE engagement_id = $1 ORDER BY updated_at DESC`,
      [engagementId],
    );
    return result.rows.map(mapBreaker);
  }
}

// ---------------------------------------------------------------------------
// Outbox (§44-§45)
// ---------------------------------------------------------------------------

export class OutboxRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async append(input: {
    eventType: string;
    engagementId?: string | null;
    aggregateId: string;
    causationId?: string | null;
    correlationId?: string | null;
    payload: Record<string, unknown>;
  }): Promise<OutboxEventRecord> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(90211)');
      const seqResult = await client.query<{ seq: string | null }>(
        'SELECT MAX(sequence) AS seq FROM outbox_events WHERE aggregate_id = $1',
        [input.aggregateId],
      );
      const sequence = Number(seqResult.rows[0]?.seq ?? 0) + 1;
      const id = generateId('OBX');
      const result = await client.query(
        `INSERT INTO outbox_events (id, event_type, engagement_id, aggregate_id, causation_id,
                                    correlation_id, sequence, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
         RETURNING id, event_type, engagement_id, aggregate_id, causation_id, correlation_id,
                   sequence, payload, status, attempts, created_at, delivered_at`,
        [
          id,
          input.eventType,
          input.engagementId ?? null,
          input.aggregateId,
          input.causationId ?? null,
          input.correlationId ?? null,
          sequence,
          JSON.stringify(input.payload),
        ],
      );
      await client.query('COMMIT');
      return mapOutbox(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async markDelivered(id: string): Promise<void> {
    await this.pool.query(
      `UPDATE outbox_events SET status = 'DELIVERED', delivered_at = now() WHERE id = $1`,
      [id],
    );
  }

  async markFailed(id: string): Promise<void> {
    await this.pool.query(
      `UPDATE outbox_events
         SET status = CASE WHEN attempts + 1 >= 5 THEN 'ABANDONED' ELSE 'FAILED' END,
             attempts = attempts + 1
       WHERE id = $1`,
      [id],
    );
  }

  async listPending(limit = 50): Promise<OutboxEventRecord[]> {
    const result = await this.pool.query(
      `SELECT id, event_type, engagement_id, aggregate_id, causation_id, correlation_id,
              sequence, payload, status, attempts, created_at, delivered_at
       FROM outbox_events WHERE status IN ('PENDING', 'FAILED')
       ORDER BY created_at ASC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapOutbox);
  }

  async countPending(): Promise<number> {
    const result = await this.pool.query<{ count: number }>(
      `SELECT COUNT(*)::int AS count FROM outbox_events WHERE status IN ('PENDING', 'FAILED')`,
    );
    return result.rows[0]?.count ?? 0;
  }
}

// ---------------------------------------------------------------------------
// Retention + backups + emergency stop (§59, §62, §89)
// ---------------------------------------------------------------------------

export class RetentionPoliciesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async list(): Promise<RetentionPolicyRecord[]> {
    const result = await this.pool.query(
      'SELECT id, data_class, retention_days, hard_delete, created_at, updated_at FROM retention_policies ORDER BY data_class',
    );
    return result.rows.map(mapRetention);
  }

  async update(dataClass: string, retentionDays: number, hardDelete: boolean): Promise<RetentionPolicyRecord | null> {
    const result = await this.pool.query(
      `UPDATE retention_policies SET retention_days = $2, hard_delete = $3, updated_at = now()
       WHERE data_class = $1
       RETURNING id, data_class, retention_days, hard_delete, created_at, updated_at`,
      [dataClass, retentionDays, hardDelete],
    );
    return result.rows[0] ? mapRetention(result.rows[0]) : null;
  }

  async findByClass(dataClass: string): Promise<RetentionPolicyRecord | null> {
    const result = await this.pool.query(
      'SELECT id, data_class, retention_days, hard_delete, created_at, updated_at FROM retention_policies WHERE data_class = $1',
      [dataClass],
    );
    return result.rows[0] ? mapRetention(result.rows[0]) : null;
  }
}

export class BackupRecordsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: {
    label: string;
    filePath: string;
    sha256: string;
    sizeBytes: number;
    migrationsApplied: number;
  }): Promise<BackupRecordRecord> {
    const id = generateId('BKP');
    const result = await this.pool.query(
      `INSERT INTO backup_records (id, label, file_path, sha256, size_bytes, migrations_applied)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, label, file_path, sha256, size_bytes, migrations_applied, restore_verified_at, created_at`,
      [id, input.label, input.filePath, input.sha256, input.sizeBytes, input.migrationsApplied],
    );
    return mapBackup(result.rows[0]!);
  }

  async markRestoreVerified(id: string): Promise<boolean> {
    const result = await this.pool.query(
      'UPDATE backup_records SET restore_verified_at = now() WHERE id = $1 AND restore_verified_at IS NULL',
      [id],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async listLatest(limit = 20): Promise<BackupRecordRecord[]> {
    const result = await this.pool.query(
      'SELECT id, label, file_path, sha256, size_bytes, migrations_applied, restore_verified_at, created_at FROM backup_records ORDER BY created_at DESC LIMIT $1',
      [Math.min(Math.max(limit, 1), 100)],
    );
    return result.rows.map(mapBackup);
  }
}

export class EmergencyStopRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async getState(): Promise<EmergencyStopRecord> {
    const result = await this.pool.query(
      'SELECT status, engaged_at, released_at, engaged_by, reason, cancelled_tasks, revoked_grants FROM emergency_stop WHERE id = $1',
      ['EST_PLATFORM'],
    );
    return mapEmergencyStop(result.rows[0]!);
  }

  async engage(input: { engagedBy: string; reason: string; cancelledTasks: number; revokedGrants: number }): Promise<EmergencyStopRecord> {
    const result = await this.pool.query(
      `UPDATE emergency_stop
         SET status = 'ENGAGED', engaged_at = now(), released_at = NULL, engaged_by = $1,
             reason = $2, cancelled_tasks = $3, revoked_grants = $4
       WHERE id = 'EST_PLATFORM' AND status = 'CLEAR'
       RETURNING status, engaged_at, released_at, engaged_by, reason, cancelled_tasks, revoked_grants`,
      [input.engagedBy, input.reason, input.cancelledTasks, input.revokedGrants],
    );
    return mapEmergencyStop(result.rows[0]!);
  }

  async release(): Promise<EmergencyStopRecord> {
    const result = await this.pool.query(
      `UPDATE emergency_stop
         SET status = 'CLEAR', released_at = now(), reason = NULL
       WHERE id = 'EST_PLATFORM' AND status = 'ENGAGED'
       RETURNING status, engaged_at, released_at, engaged_by, reason, cancelled_tasks, revoked_grants`,
    );
    return mapEmergencyStop(result.rows[0]!);
  }

  /** Hot-path check: cheap single-row read used before target-bound actions. */
  async isEngaged(): Promise<boolean> {
    const result = await this.pool.query<{ status: string }>(
      'SELECT status FROM emergency_stop WHERE id = $1',
      ['EST_PLATFORM'],
    );
    return result.rows[0]?.status === 'ENGAGED';
  }
}

// ---------------------------------------------------------------------------
// Row mappers
// ---------------------------------------------------------------------------

type ApiCredentialRow = {
  id: string;
  user_id: string;
  kind: string;
  name: string;
  token_hash: string;
  scopes: string[];
  status: string;
  created_at: Date;
  expires_at: Date;
  last_used_at: Date | null;
  revoked_at: Date | null;
};

function mapApiCredential(row: ApiCredentialRow): ApiCredentialRecord {
  return {
    id: row.id,
    user_id: row.user_id,
    kind: row.kind as ApiCredentialRecord['kind'],
    name: row.name,
    token_hash: row.token_hash,
    scopes: row.scopes,
    status: row.status as ApiCredentialRecord['status'],
    created_at: requireIso(row.created_at),
    expires_at: requireIso(row.expires_at),
    last_used_at: row.last_used_at ? requireIso(row.last_used_at) : null,
    revoked_at: row.revoked_at ? requireIso(row.revoked_at) : null,
  };
}

type GrantRow = {
  id: string;
  engagement_id: string;
  identity_id: string;
  target_id: string;
  secret_reference: string;
  purpose: string;
  status: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  consumed_at: Date | null;
};

function mapGrant(row: GrantRow): CredentialGrantRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    identity_id: row.identity_id,
    target_id: row.target_id,
    secret_reference: row.secret_reference,
    purpose: row.purpose as CredentialGrantRecord['purpose'],
    status: row.status as CredentialGrantRecord['status'],
    created_at: requireIso(row.created_at),
    expires_at: requireIso(row.expires_at),
    revoked_at: row.revoked_at ? requireIso(row.revoked_at) : null,
    consumed_at: row.consumed_at ? requireIso(row.consumed_at) : null,
  };
}

type ScopeVersionRow = {
  id: string;
  engagement_id: string;
  version: number;
  status: string;
  scope: Record<string, unknown>;
  diff: Record<string, unknown>;
  created_by: string;
  created_at: Date;
  activated_at: Date | null;
};

function mapScopeVersion(row: ScopeVersionRow): ScopeVersionRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    version: Number(row.version),
    status: row.status as ScopeVersionRecord['status'],
    scope: row.scope,
    diff: row.diff,
    created_by: row.created_by,
    created_at: requireIso(row.created_at),
    activated_at: row.activated_at ? requireIso(row.activated_at) : null,
  };
}

type SecurityEventRow = {
  id: string;
  incident_id: string | null;
  severity: string;
  category: string;
  actor: string;
  engagement_id: string | null;
  description: string;
  metadata: Record<string, unknown>;
  created_at: Date;
};

function mapSecurityEvent(row: SecurityEventRow): SecurityEventRecord {
  return {
    id: row.id,
    incident_id: row.incident_id,
    severity: row.severity as SecurityEventRecord['severity'],
    category: row.category,
    actor: row.actor as SecurityEventRecord['actor'],
    engagement_id: row.engagement_id,
    description: row.description,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
  };
}

type IncidentRow = {
  id: string;
  status: string;
  severity: string;
  title: string;
  opened_at: Date;
  resolved_at: Date | null;
  event_count?: number;
};

function mapIncident(row: IncidentRow): IncidentRecord {
  return {
    id: row.id,
    status: row.status as IncidentRecord['status'],
    severity: row.severity as IncidentRecord['severity'],
    title: row.title,
    opened_at: requireIso(row.opened_at),
    resolved_at: row.resolved_at ? requireIso(row.resolved_at) : null,
    event_count: row.event_count ?? 0,
  };
}

type BreakerRow = {
  id: string;
  subject: string;
  subject_id: string;
  engagement_id: string | null;
  category: string;
  state: string;
  violation_count: number;
  threshold: number;
  tripped_at: Date | null;
  reset_at: Date | null;
  updated_at: Date;
};

function mapBreaker(row: BreakerRow): CircuitBreakerRecord {
  return {
    id: row.id,
    subject: row.subject as CircuitBreakerRecord['subject'],
    subject_id: row.subject_id,
    engagement_id: row.engagement_id,
    category: row.category,
    state: row.state as CircuitBreakerRecord['state'],
    violation_count: Number(row.violation_count),
    threshold: Number(row.threshold),
    tripped_at: row.tripped_at ? requireIso(row.tripped_at) : null,
    reset_at: row.reset_at ? requireIso(row.reset_at) : null,
    updated_at: requireIso(row.updated_at),
  };
}

type OutboxRow = {
  id: string;
  event_type: string;
  engagement_id: string | null;
  aggregate_id: string;
  causation_id: string | null;
  correlation_id: string | null;
  sequence: number | string;
  payload: Record<string, unknown>;
  status: string;
  attempts: number;
  created_at: Date;
  delivered_at: Date | null;
};

function mapOutbox(row: OutboxRow): OutboxEventRecord {
  return {
    id: row.id,
    event_type: row.event_type,
    engagement_id: row.engagement_id,
    aggregate_id: row.aggregate_id,
    causation_id: row.causation_id,
    correlation_id: row.correlation_id,
    sequence: Number(row.sequence),
    payload: row.payload ?? {},
    status: row.status as OutboxEventRecord['status'],
    attempts: Number(row.attempts),
    created_at: requireIso(row.created_at),
    delivered_at: row.delivered_at ? requireIso(row.delivered_at) : null,
  };
}

type RetentionRow = {
  id: string;
  data_class: string;
  retention_days: number;
  hard_delete: boolean;
  created_at: Date;
  updated_at: Date;
};

function mapRetention(row: RetentionRow): RetentionPolicyRecord {
  return {
    id: row.id,
    data_class: row.data_class,
    retention_days: Number(row.retention_days),
    hard_delete: row.hard_delete,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}

type BackupRow = {
  id: string;
  label: string;
  file_path: string;
  sha256: string;
  size_bytes: number | string;
  migrations_applied: number;
  restore_verified_at: Date | null;
  created_at: Date;
};

function mapBackup(row: BackupRow): BackupRecordRecord {
  return {
    id: row.id,
    label: row.label,
    file_path: row.file_path,
    sha256: row.sha256,
    size_bytes: Number(row.size_bytes),
    migrations_applied: Number(row.migrations_applied),
    restore_verified_at: row.restore_verified_at ? requireIso(row.restore_verified_at) : null,
    created_at: requireIso(row.created_at),
  };
}

type EmergencyStopRow = {
  status: string;
  engaged_at: Date | null;
  released_at: Date | null;
  engaged_by: string | null;
  reason: string | null;
  cancelled_tasks: number;
  revoked_grants: number;
};

function mapEmergencyStop(row: EmergencyStopRow): EmergencyStopRecord {
  return {
    status: row.status as EmergencyStopRecord['status'],
    engaged_at: row.engaged_at ? requireIso(row.engaged_at) : null,
    released_at: row.released_at ? requireIso(row.released_at) : null,
    engaged_by: row.engaged_by,
    reason: row.reason,
    cancelled_tasks: Number(row.cancelled_tasks),
    revoked_grants: Number(row.revoked_grants),
  };
}
