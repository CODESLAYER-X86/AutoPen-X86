import type { Pool } from 'pg';
import { generateId, type FindingStatus } from '@aegis/shared';
import type { FindingRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const FINDING_COLUMNS =
  'id, engagement_id, hypothesis_id, title, description, severity, status, evidence_ids, created_at, updated_at';

export interface CreateFindingInput {
  engagementId: string;
  hypothesisId: string | null;
  title: string;
  description: string;
  severity: string;
  evidenceIds?: string[];
  /** Promotion status (§55): findings promoted from CONFIRMED hypotheses are CONFIRMED. */
  status?: FindingStatus;
}

export class FindingsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateFindingInput): Promise<FindingRecord> {
    const id = generateId('FND');
    const result = await this.pool.query(
      `INSERT INTO findings (id, engagement_id, hypothesis_id, title, description, severity, status, evidence_ids)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
       RETURNING ${FINDING_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.title,
        input.description,
        input.severity,
        input.status ?? 'PROPOSED',
        JSON.stringify(input.evidenceIds ?? []),
      ],
    );
    return mapFinding(result.rows[0]!);
  }

  async updateStatus(id: string, status: FindingStatus): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `UPDATE findings SET status = $2, updated_at = now() WHERE id = $1
       RETURNING ${FINDING_COLUMNS}`,
      [id, status],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  async findByHypothesis(hypothesisId: string): Promise<FindingRecord | null> {
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings WHERE hypothesis_id = $1 LIMIT 1`,
      [hypothesisId],
    );
    return result.rows[0] ? mapFinding(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: readonly FindingStatus[]; limit?: number } = {},
  ): Promise<FindingRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 500);
    if (options.statuses && options.statuses.length > 0) {
      const result = await this.pool.query(
        `SELECT ${FINDING_COLUMNS} FROM findings
         WHERE engagement_id = $1 AND status = ANY($2::text[])
         ORDER BY created_at DESC LIMIT $3`,
        [engagementId, [...options.statuses], limit],
      );
      return result.rows.map(mapFinding);
    }
    const result = await this.pool.query(
      `SELECT ${FINDING_COLUMNS} FROM findings WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, limit],
    );
    return result.rows.map(mapFinding);
  }
}

type FindingRow = {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  title: string;
  description: string;
  severity: string;
  status: FindingStatus;
  evidence_ids: string[];
  created_at: Date;
  updated_at: Date;
};

export function mapFinding(row: FindingRow): FindingRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    hypothesis_id: row.hypothesis_id,
    title: row.title,
    description: row.description,
    severity: row.severity,
    status: row.status,
    evidence_ids: row.evidence_ids ?? [],
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
