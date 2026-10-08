import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { StrategyRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const STRATEGY_COLUMNS =
  'id, engagement_id, run_id, version, summary, focus, reason, created_at';

export interface CreateStrategyInput {
  engagementId: string;
  runId: string | null;
  summary: string;
  focus: string;
  reason: string;
}

export class StrategiesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /** Creates the next version atomically (version = max + 1). */
  async createNext(input: CreateStrategyInput): Promise<StrategyRecord> {
    const id = generateId('STG');
    const result = await this.pool.query(
      `INSERT INTO strategies (id, engagement_id, run_id, version, summary, focus, reason)
       VALUES ($1, $2, $3,
               COALESCE((SELECT max(version) + 1 FROM strategies WHERE engagement_id = $2), 1),
               $4, $5, $6)
       RETURNING ${STRATEGY_COLUMNS}`,
      [id, input.engagementId, input.runId, input.summary, input.focus, input.reason],
    );
    return mapStrategy(result.rows[0]!);
  }

  async latestByEngagement(engagementId: string): Promise<StrategyRecord | null> {
    const result = await this.pool.query(
      `SELECT ${STRATEGY_COLUMNS} FROM strategies WHERE engagement_id = $1
       ORDER BY version DESC LIMIT 1`,
      [engagementId],
    );
    return result.rows[0] ? mapStrategy(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 20): Promise<StrategyRecord[]> {
    const result = await this.pool.query(
      `SELECT ${STRATEGY_COLUMNS} FROM strategies WHERE engagement_id = $1
       ORDER BY version DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 100)],
    );
    return result.rows.map(mapStrategy);
  }
}

type StrategyRow = {
  id: string;
  engagement_id: string;
  run_id: string | null;
  version: number;
  summary: string;
  focus: string;
  reason: string;
  created_at: Date;
};

export function mapStrategy(row: StrategyRow): StrategyRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    run_id: row.run_id,
    version: row.version,
    summary: row.summary,
    focus: row.focus,
    reason: row.reason,
    created_at: requireIso(row.created_at),
  };
}
