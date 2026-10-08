import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { ObservationRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const OBS_COLUMNS =
  'id, engagement_id, task_id, hypothesis_id, type, description, confidence, evidence_ids, metadata, created_at';

export interface CreateObservationInput {
  engagementId: string;
  taskId: string | null;
  hypothesisId: string | null;
  type: string;
  description: string;
  confidence: number;
  evidenceIds?: string[];
  metadata?: Record<string, unknown>;
}

export class ObservationsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateObservationInput): Promise<ObservationRecord> {
    const id = generateId('OBS');
    const result = await this.pool.query(
      `INSERT INTO observations
         (id, engagement_id, task_id, hypothesis_id, type, description, confidence, evidence_ids, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb)
       RETURNING ${OBS_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.taskId,
        input.hypothesisId,
        input.type,
        input.description,
        input.confidence,
        JSON.stringify(input.evidenceIds ?? []),
        JSON.stringify(input.metadata ?? {}),
      ],
    );
    return mapObservation(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<ObservationRecord[]> {
    const result = await this.pool.query(
      `SELECT ${OBS_COLUMNS} FROM observations WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapObservation);
  }

  async listByTask(taskId: string): Promise<ObservationRecord[]> {
    const result = await this.pool.query(
      `SELECT ${OBS_COLUMNS} FROM observations WHERE task_id = $1 ORDER BY created_at DESC`,
      [taskId],
    );
    return result.rows.map(mapObservation);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM observations WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n;
  }
}

type ObservationRow = {
  id: string;
  engagement_id: string;
  task_id: string | null;
  hypothesis_id: string | null;
  type: string;
  description: string;
  confidence: number;
  evidence_ids: string[];
  metadata: Record<string, unknown>;
  created_at: Date;
};

export function mapObservation(row: ObservationRow): ObservationRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    task_id: row.task_id,
    hypothesis_id: row.hypothesis_id,
    type: row.type,
    description: row.description,
    confidence: row.confidence,
    evidence_ids: row.evidence_ids ?? [],
    metadata: row.metadata ?? {},
    created_at: requireIso(row.created_at),
  };
}
