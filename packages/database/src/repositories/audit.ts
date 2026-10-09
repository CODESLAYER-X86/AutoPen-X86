import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { AuditChainRecord, AuditRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateAuditInput {
  actorUserId: string | null;
  action: string;
  resource: string;
  resourceId?: string | null;
  engagementId?: string | null;
  metadata?: Record<string, unknown>;
}

/** Deterministic JSON: jsonb normalizes key order (length, then bytewise), so the chain must hash a canonical form. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .map(([key, val]) => `${JSON.stringify(key)}:${canonicalJson(val)}`)
    .sort();
  return `{${entries.join(',')}}`;
}

/** Canonical string hashed into the tamper-evident chain (Part 8 §85). */
function chainInput(row: {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource: string;
  resource_id: string | null;
  engagement_id: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}): string {
  return [
    row.id,
    row.actor_user_id ?? '',
    row.action,
    row.resource,
    row.resource_id ?? '',
    row.engagement_id ?? '',
    canonicalJson(row.metadata ?? {}),
    row.created_at,
  ].join('|');
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export class AuditRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /**
   * Append an audit record. The insert runs inside an advisory-locked
   * transaction that reads the chain head and writes chain_seq, prev_hash
   * and content_hash atomically (Part 8 §85: tamper-resistant audit log).
   */
  async create(input: CreateAuditInput): Promise<AuditRecord> {
    const id = generateId('AUD');
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Serialize chain head access across concurrent appends.
      await client.query('SELECT pg_advisory_xact_lock(90210)');
      const head = await client.query<{ chain_seq: string; content_hash: string | null }>(
        'SELECT chain_seq, content_hash FROM audit_log ORDER BY chain_seq DESC LIMIT 1',
      );
      const seq = Number(head.rows[0]?.chain_seq ?? 0) + 1;
      const prevHash = head.rows[0]?.content_hash ?? null;
      const createdAt = new Date();
      const contentHash = sha256(
        chainInput({
          id,
          actor_user_id: input.actorUserId,
          action: input.action,
          resource: input.resource,
          resource_id: input.resourceId ?? null,
          engagement_id: input.engagementId ?? null,
          metadata: input.metadata ?? {},
          created_at: createdAt.toISOString(),
        }) + '|' + (prevHash ?? ''),
      );
      const result = await client.query(
        `INSERT INTO audit_log (id, actor_user_id, action, resource, resource_id, engagement_id,
                                metadata, chain_seq, prev_hash, content_hash, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11)
         RETURNING id, actor_user_id, action, resource, resource_id, engagement_id, metadata,
                   chain_seq, prev_hash, content_hash, created_at`,
        [
          id,
          input.actorUserId,
          input.action,
          input.resource,
          input.resourceId ?? null,
          input.engagementId ?? null,
          JSON.stringify(input.metadata ?? {}),
          seq,
          prevHash,
          contentHash,
          createdAt,
        ],
      );
      await client.query('COMMIT');
      return mapAudit(result.rows[0]!);
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Lazily backfill content_hash/prev_hash for rows that predate the chain
   * (migration 075 numbers them but cannot hash in SQL). Idempotent.
   */
  async backfillChainHashes(): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(90210)');
      const rows = await client.query<{
        id: string;
        actor_user_id: string | null;
        action: string;
        resource: string;
        resource_id: string | null;
        engagement_id: string | null;
        metadata: Record<string, unknown>;
        chain_seq: string;
        created_at: Date;
      }>(
        `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata, chain_seq, created_at
           FROM audit_log WHERE content_hash IS NULL ORDER BY chain_seq ASC`,
      );
      let prevHash: string | null = null;
      let backfilled = 0;
      for (const row of rows.rows) {
        const contentHash = sha256(
          chainInput({
            id: row.id,
            actor_user_id: row.actor_user_id,
            action: row.action,
            resource: row.resource,
            resource_id: row.resource_id,
            engagement_id: row.engagement_id,
            metadata: row.metadata ?? {},
            created_at: requireIso(row.created_at),
          }) + '|' + (prevHash ?? ''),
        );
        await client.query(
          'UPDATE audit_log SET prev_hash = $1, content_hash = $2 WHERE id = $3',
          [prevHash, contentHash, row.id],
        );
        prevHash = contentHash;
        backfilled += 1;
      }
      await client.query('COMMIT');
      return backfilled;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Verify the tamper-evident chain end to end. Returns the first broken
   * record when a stored hash does not match recomputation (Part 8 §85).
   */
  async verifyChain(limit = 5000): Promise<{
    verified: boolean;
    recordsChecked: number;
    firstBrokenRecordId: string | null;
    reason: string | null;
  }> {
    const result = await this.pool.query<{
      id: string;
      actor_user_id: string | null;
      action: string;
      resource: string;
      resource_id: string | null;
      engagement_id: string | null;
      metadata: Record<string, unknown>;
      chain_seq: string;
      prev_hash: string | null;
      content_hash: string | null;
      created_at: Date;
    }>(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata,
              chain_seq, prev_hash, content_hash, created_at
         FROM audit_log ORDER BY chain_seq ASC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 50000)],
    );
    let prevHash: string | null = null;
    let recordsChecked = 0;
    for (const row of result.rows) {
      const expected = sha256(
        chainInput({
          id: row.id,
          actor_user_id: row.actor_user_id,
          action: row.action,
          resource: row.resource,
          resource_id: row.resource_id,
          engagement_id: row.engagement_id,
          metadata: row.metadata ?? {},
          created_at: requireIso(row.created_at),
        }) + '|' + (prevHash ?? ''),
      );
      if (row.content_hash !== null) {
        if (row.content_hash !== expected) {
          return {
            verified: false,
            recordsChecked,
            firstBrokenRecordId: row.id,
            reason: `content_hash mismatch for ${row.id}: stored ${row.content_hash}, recomputed ${expected}`,
          };
        }
        if (row.prev_hash !== prevHash) {
          return {
            verified: false,
            recordsChecked,
            firstBrokenRecordId: row.id,
            reason: `prev_hash mismatch for ${row.id}: chain was reordered or a record was removed`,
          };
        }
      }
      prevHash = row.content_hash ?? expected;
      recordsChecked += 1;
    }
    return { verified: true, recordsChecked, firstBrokenRecordId: null, reason: null };
  }

  async listChain(limit = 100): Promise<AuditChainRecord[]> {
    const result = await this.pool.query(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata,
              chain_seq, prev_hash, content_hash, created_at
         FROM audit_log ORDER BY chain_seq DESC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map((row) => ({
      ...mapAudit(row),
      chain_seq: Number(row.chain_seq),
      prev_hash: row.prev_hash,
      content_hash: row.content_hash,
    }));
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<AuditRecord[]> {
    const result = await this.pool.query(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata,
              chain_seq, prev_hash, content_hash, created_at
       FROM audit_log WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapAudit);
  }

  async listByActor(actorUserId: string, limit = 100): Promise<AuditRecord[]> {
    const result = await this.pool.query(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata,
              chain_seq, prev_hash, content_hash, created_at
       FROM audit_log WHERE actor_user_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [actorUserId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapAudit);
  }
}

type AuditRow = {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource: string;
  resource_id: string | null;
  engagement_id: string | null;
  metadata: Record<string, unknown>;
  chain_seq?: string | number;
  prev_hash?: string | null;
  content_hash?: string | null;
  created_at: Date;
};

function mapAudit(row: AuditRow): AuditRecord {
  return {
    id: row.id,
    actor_user_id: row.actor_user_id,
    action: row.action,
    resource: row.resource,
    resource_id: row.resource_id,
    engagement_id: row.engagement_id,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
  };
}
