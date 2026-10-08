import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { AuditRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateAuditInput {
  actorUserId: string | null;
  action: string;
  resource: string;
  resourceId?: string | null;
  engagementId?: string | null;
  metadata?: Record<string, unknown>;
}

export class AuditRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAuditInput): Promise<AuditRecord> {
    const id = generateId('AUD');
    const result = await this.pool.query(
      `INSERT INTO audit_log (id, actor_user_id, action, resource, resource_id, engagement_id, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id, actor_user_id, action, resource, resource_id, engagement_id, metadata, created_at`,
      [
        id,
        input.actorUserId,
        input.action,
        input.resource,
        input.resourceId ?? null,
        input.engagementId ?? null,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapAudit(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<AuditRecord[]> {
    const result = await this.pool.query(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata, created_at
       FROM audit_log WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapAudit);
  }

  async listByActor(actorUserId: string, limit = 100): Promise<AuditRecord[]> {
    const result = await this.pool.query(
      `SELECT id, actor_user_id, action, resource, resource_id, engagement_id, metadata, created_at
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
