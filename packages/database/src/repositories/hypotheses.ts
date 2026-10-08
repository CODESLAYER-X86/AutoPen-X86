import type { Pool } from 'pg';
import { generateId, type HypothesisStatus, type HypothesisType } from '@aegis/shared';
import type { HypothesisLinkRecord, HypothesisRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const HYP_COLUMNS =
  'id, engagement_id, type, statement, status, confidence, priority, source, parent_hypothesis_id, created_at, updated_at, confirmed_at, disproved_at';

export interface CreateHypothesisInput {
  engagementId: string;
  type: HypothesisType;
  statement: string;
  status?: HypothesisStatus;
  confidence?: number;
  priority?: number;
  source: string;
  parentHypothesisId?: string | null;
}

export interface UpdateHypothesisInput {
  status?: HypothesisStatus;
  confidence?: number;
  priority?: number;
  statement?: string;
}

/** Statuses that count as "actionable" for branch budgets (Part 2 §54). */
export const ACTIONABLE_HYPOTHESIS_STATUSES: readonly HypothesisStatus[] = [
  'PROPOSED',
  'ACTIVE',
  'TESTING',
  'SUPPORTED',
];

export class HypothesesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateHypothesisInput): Promise<HypothesisRecord> {
    const id = generateId('HYP');
    const result = await this.pool.query(
      `INSERT INTO hypotheses
         (id, engagement_id, type, statement, status, confidence, priority, source, parent_hypothesis_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING ${HYP_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.type,
        input.statement,
        input.status ?? 'PROPOSED',
        input.confidence ?? 0.5,
        input.priority ?? 0.5,
        input.source,
        input.parentHypothesisId ?? null,
      ],
    );
    return mapHypothesis(result.rows[0]!);
  }

  async findById(id: string): Promise<HypothesisRecord | null> {
    const result = await this.pool.query(`SELECT ${HYP_COLUMNS} FROM hypotheses WHERE id = $1`, [id]);
    return result.rows[0] ? mapHypothesis(result.rows[0]) : null;
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<HypothesisRecord | null> {
    const result = await this.pool.query(
      `SELECT ${HYP_COLUMNS} FROM hypotheses WHERE id = $1 AND engagement_id = $2`,
      [id, engagementId],
    );
    return result.rows[0] ? mapHypothesis(result.rows[0]) : null;
  }

  /**
   * Single deterministic write path. Timestamps for confirmed/disproved are
   * set by the transition semantics, not by callers (Part 2 §25).
   */
  async update(id: string, patch: UpdateHypothesisInput): Promise<HypothesisRecord | null> {
    const result = await this.pool.query(
      `UPDATE hypotheses SET
         status = COALESCE($2, status),
         confidence = COALESCE($3, confidence),
         priority = COALESCE($4, priority),
         statement = COALESCE($5, statement),
         confirmed_at = CASE WHEN $2 = 'CONFIRMED' THEN now() ELSE confirmed_at END,
         disproved_at = CASE WHEN $2 = 'DISPROVED' THEN now() ELSE disproved_at END,
         updated_at = now()
       WHERE id = $1
       RETURNING ${HYP_COLUMNS}`,
      [
        id,
        patch.status ?? null,
        patch.confidence ?? null,
        patch.priority ?? null,
        patch.statement ?? null,
      ],
    );
    return result.rows[0] ? mapHypothesis(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: readonly HypothesisStatus[]; limit?: number } = {},
  ): Promise<HypothesisRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 500);
    if (options.statuses && options.statuses.length > 0) {
      const result = await this.pool.query(
        `SELECT ${HYP_COLUMNS} FROM hypotheses
         WHERE engagement_id = $1 AND status = ANY($2::text[])
         ORDER BY priority DESC, updated_at DESC LIMIT $3`,
        [engagementId, [...options.statuses], limit],
      );
      return result.rows.map(mapHypothesis);
    }
    const result = await this.pool.query(
      `SELECT ${HYP_COLUMNS} FROM hypotheses
       WHERE engagement_id = $1 ORDER BY priority DESC, updated_at DESC LIMIT $2`,
      [engagementId, limit],
    );
    return result.rows.map(mapHypothesis);
  }

  async countByStatus(engagementId: string): Promise<Record<HypothesisStatus, number>> {
    const result = await this.pool.query<{ status: HypothesisStatus; n: number }>(
      'SELECT status, count(*)::int AS n FROM hypotheses WHERE engagement_id = $1 GROUP BY status',
      [engagementId],
    );
    const counts = {
      PROPOSED: 0,
      ACTIVE: 0,
      TESTING: 0,
      SUPPORTED: 0,
      CONFIRMED: 0,
      DISPROVED: 0,
      ABANDONED: 0,
    } as Record<HypothesisStatus, number>;
    for (const row of result.rows) counts[row.status] = row.n;
    return counts;
  }

  async countActionable(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM hypotheses WHERE engagement_id = $1 AND status = ANY($2::text[])',
      [engagementId, [...ACTIONABLE_HYPOTHESIS_STATUSES]],
    );
    return result.rows[0]!.n;
  }

  /** Depth of the deepest branch (Part 2 §54 max_branch_depth). */
  async maxBranchDepth(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ depth: number | null }>(
      `WITH RECURSIVE tree AS (
         SELECT id, parent_hypothesis_id, 1 AS depth FROM hypotheses WHERE engagement_id = $1
         UNION ALL
         SELECT h.id, h.parent_hypothesis_id, t.depth + 1
         FROM hypotheses h JOIN tree t ON h.parent_hypothesis_id = t.id
         WHERE h.engagement_id = $1
       )
       SELECT max(depth) AS depth FROM tree`,
      [engagementId],
    );
    return result.rows[0]?.depth ?? 0;
  }

  async link(input: {
    hypothesisId: string;
    refType: 'OBSERVATION' | 'TEST' | 'EVIDENCE';
    refId: string;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO hypothesis_links (id, hypothesis_id, ref_type, ref_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (hypothesis_id, ref_type, ref_id) DO NOTHING`,
      [generateId('EVT'), input.hypothesisId, input.refType, input.refId],
    );
  }

  async linksByHypothesis(hypothesisId: string): Promise<HypothesisLinkRecord[]> {
    const result = await this.pool.query(
      'SELECT id, hypothesis_id, ref_type, ref_id, created_at FROM hypothesis_links WHERE hypothesis_id = $1',
      [hypothesisId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      hypothesis_id: row.hypothesis_id,
      ref_type: row.ref_type,
      ref_id: row.ref_id,
      created_at: requireIso(row.created_at),
    }));
  }
}

type HypothesisRow = {
  id: string;
  engagement_id: string;
  type: HypothesisType;
  statement: string;
  status: HypothesisStatus;
  confidence: number;
  priority: number;
  source: string;
  parent_hypothesis_id: string | null;
  created_at: Date;
  updated_at: Date;
  confirmed_at: Date | null;
  disproved_at: Date | null;
};

export function mapHypothesis(row: HypothesisRow): HypothesisRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    type: row.type,
    statement: row.statement,
    status: row.status,
    confidence: row.confidence,
    priority: row.priority,
    source: row.source,
    parent_hypothesis_id: row.parent_hypothesis_id,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
    confirmed_at: row.confirmed_at ? requireIso(row.confirmed_at) : null,
    disproved_at: row.disproved_at ? requireIso(row.disproved_at) : null,
  };
}
