import type { Pool } from 'pg';
import { generateId, type TargetType } from '@aegis/shared';
import type { TargetRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateTargetInput {
  engagementId: string;
  type: TargetType;
  value: string;
  label?: string | null;
  metadata?: Record<string, unknown>;
}

export class TargetsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateTargetInput): Promise<TargetRecord> {
    const id = generateId('TGT');
    const result = await this.pool.query(
      `INSERT INTO targets (id, engagement_id, type, value, label, metadata)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)
       RETURNING id, engagement_id, type, value, label, metadata, created_at, updated_at`,
      [id, input.engagementId, input.type, input.value, input.label ?? null, JSON.stringify(input.metadata ?? {})],
    );
    return mapTarget(result.rows[0]!);
  }

  async listByEngagement(engagementId: string): Promise<TargetRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, type, value, label, metadata, created_at, updated_at
       FROM targets WHERE engagement_id = $1 ORDER BY created_at ASC`,
      [engagementId],
    );
    return result.rows.map(mapTarget);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS n FROM targets WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n as number;
  }
}

type TargetRow = {
  id: string;
  engagement_id: string;
  type: TargetType;
  value: string;
  label: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
};

function mapTarget(row: TargetRow): TargetRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    type: row.type,
    value: row.value,
    label: row.label,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
