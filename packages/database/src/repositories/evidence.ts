import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { EvidenceRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface InsertEvidenceInput {
  engagementId: string;
  type: string;
  source: string;
  contentReference: string;
  sha256: string;
  parentId?: string | null;
  taskId?: string | null;
  metadata?: Record<string, unknown>;
}

export class EvidenceRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertEvidenceInput): Promise<EvidenceRecord> {
    const id = generateId('EVD');
    const result = await this.pool.query(
      `INSERT INTO evidence (id, engagement_id, type, source, content_reference, sha256, parent_id, task_id, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
       RETURNING id, engagement_id, type, source, content_reference, sha256, parent_id, task_id, metadata, created_at`,
      [
        id,
        input.engagementId,
        input.type,
        input.source,
        input.contentReference,
        input.sha256,
        input.parentId ?? null,
        input.taskId ?? null,
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapEvidence(result.rows[0]!);
  }

  async findById(id: string): Promise<EvidenceRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, type, source, content_reference, sha256, parent_id, task_id, metadata, created_at
       FROM evidence WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapEvidence(result.rows[0]) : null;
  }

  async findBySha(engagementId: string, sha256: string): Promise<EvidenceRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, type, source, content_reference, sha256, parent_id, task_id, metadata, created_at
       FROM evidence WHERE engagement_id = $1 AND sha256 = $2`,
      [engagementId, sha256],
    );
    return result.rows[0] ? mapEvidence(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string): Promise<EvidenceRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, type, source, content_reference, sha256, parent_id, task_id, metadata, created_at
       FROM evidence WHERE engagement_id = $1
       ORDER BY created_at DESC`,
      [engagementId],
    );
    return result.rows.map(mapEvidence);
  }
}

type EvidenceRow = {
  id: string;
  engagement_id: string;
  type: string;
  source: string;
  content_reference: string;
  sha256: string;
  parent_id: string | null;
  task_id: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
};

export function mapEvidence(row: EvidenceRow): EvidenceRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    type: row.type,
    source: row.source,
    content_reference: row.content_reference,
    sha256: row.sha256,
    parent_id: row.parent_id,
    task_id: row.task_id,
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
  };
}
