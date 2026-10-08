import type { Pool } from 'pg';
import { generateId, type AssetType } from '@aegis/shared';
import type { AssetRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateAssetInput {
  engagementId: string;
  type: AssetType;
  value: string;
  label?: string | null;
  parentId?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Assets discovered during reconnaissance. No HTTP API yet (attack-surface
 * graph arrives in a later part) — the repository is the foundation.
 */
export class AssetsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAssetInput): Promise<AssetRecord> {
    const id = generateId('AST');
    const result = await this.pool.query(
      `INSERT INTO assets (id, engagement_id, type, value, label, parent_id, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id, engagement_id, type, value, label, parent_id, metadata, created_at, updated_at`,
      [id, input.engagementId, input.type, input.value, input.label ?? null, input.parentId ?? null, JSON.stringify(input.metadata ?? {})],
    );
    return mapAsset(result.rows[0]!);
  }

  async listByEngagement(engagementId: string): Promise<AssetRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, type, value, label, parent_id, metadata, created_at, updated_at
       FROM assets WHERE engagement_id = $1 ORDER BY created_at ASC`,
      [engagementId],
    );
    return result.rows.map(mapAsset);
  }
}

type AssetRow = {
  id: string;
  engagement_id: string;
  type: AssetType;
  value: string;
  label: string | null;
  parent_id: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
};

function mapAsset(row: AssetRow): AssetRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    type: row.type,
    value: row.value,
    label: row.label,
    parent_id: row.parent_id,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
