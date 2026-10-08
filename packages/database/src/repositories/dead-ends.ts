import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { DeadEndRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const DEAD_END_COLUMNS =
  'id, engagement_id, hypothesis_id, description, tests, reason, created_at';

export interface CreateDeadEndInput {
  engagementId: string;
  hypothesisId: string | null;
  description: string;
  tests: string[];
  reason: string;
}

export class DeadEndsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateDeadEndInput): Promise<DeadEndRecord> {
    const id = generateId('DDE');
    const result = await this.pool.query(
      `INSERT INTO dead_ends (id, engagement_id, hypothesis_id, description, tests, reason)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)
       RETURNING ${DEAD_END_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.description,
        JSON.stringify(input.tests),
        input.reason,
      ],
    );
    return mapDeadEnd(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<DeadEndRecord[]> {
    const result = await this.pool.query(
      `SELECT ${DEAD_END_COLUMNS} FROM dead_ends WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapDeadEnd);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM dead_ends WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n;
  }
}

type DeadEndRow = {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  description: string;
  tests: string[];
  reason: string;
  created_at: Date;
};

export function mapDeadEnd(row: DeadEndRow): DeadEndRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    hypothesis_id: row.hypothesis_id,
    description: row.description,
    tests: row.tests ?? [],
    reason: row.reason,
    created_at: requireIso(row.created_at),
  };
}
