import type { Pool } from 'pg';
import { generateId, type EngagementMode, type EngagementStatus } from '@aegis/shared';
import type { EngagementRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export interface CreateEngagementInput {
  projectId: string;
  name: string;
  mode: EngagementMode;
  description: string;
}

export class EngagementsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateEngagementInput): Promise<EngagementRecord> {
    const id = generateId('ENG');
    const result = await this.pool.query(
      `INSERT INTO engagements (id, project_id, name, mode, description)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, project_id, name, mode, status, description,
                 started_at, completed_at, created_at, updated_at`,
      [id, input.projectId, input.name, input.mode, input.description],
    );
    return mapEngagement(result.rows[0]!);
  }

  async findById(id: string): Promise<EngagementRecord | null> {
    const result = await this.pool.query(
      `SELECT id, project_id, name, mode, status, description,
              started_at, completed_at, created_at, updated_at
       FROM engagements WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapEngagement(result.rows[0]) : null;
  }

  async listByProject(projectId: string): Promise<EngagementRecord[]> {
    const result = await this.pool.query(
      `SELECT id, project_id, name, mode, status, description,
              started_at, completed_at, created_at, updated_at
       FROM engagements WHERE project_id = $1
       ORDER BY created_at DESC`,
      [projectId],
    );
    return result.rows.map(mapEngagement);
  }

  /**
   * Single deterministic write path for status transitions. Timestamps are
   * set as side effects of the transition semantics (not by callers).
   */
  async updateStatus(id: string, status: EngagementStatus): Promise<EngagementRecord | null> {
    const result = await this.pool.query(
      `UPDATE engagements SET
         status = $2,
         started_at = CASE WHEN $2 = 'RUNNING' AND started_at IS NULL THEN now() ELSE started_at END,
         completed_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE completed_at END,
         updated_at = now()
       WHERE id = $1
       RETURNING id, project_id, name, mode, status, description,
                 started_at, completed_at, created_at, updated_at`,
      [id, status],
    );
    return result.rows[0] ? mapEngagement(result.rows[0]) : null;
  }

  async updateFields(
    id: string,
    patch: { name?: string; description?: string },
  ): Promise<EngagementRecord | null> {
    const result = await this.pool.query(
      `UPDATE engagements SET
         name = COALESCE($2, name),
         description = COALESCE($3, description),
         updated_at = now()
       WHERE id = $1
       RETURNING id, project_id, name, mode, status, description,
                 started_at, completed_at, created_at, updated_at`,
      [id, patch.name ?? null, patch.description ?? null],
    );
    return result.rows[0] ? mapEngagement(result.rows[0]) : null;
  }

  async countByProject(projectId: string): Promise<number> {
    const result = await this.pool.query(
      'SELECT count(*)::int AS n FROM engagements WHERE project_id = $1',
      [projectId],
    );
    return result.rows[0]!.n as number;
  }
}

type EngagementRow = {
  id: string;
  project_id: string;
  name: string;
  mode: EngagementMode;
  status: EngagementStatus;
  description: string;
  started_at: Date | null;
  completed_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

export function mapEngagement(row: EngagementRow): EngagementRecord {
  return {
    id: row.id,
    project_id: row.project_id,
    name: row.name,
    mode: row.mode,
    status: row.status,
    description: row.description,
    started_at: row.started_at ? requireIso(row.started_at) : null,
    completed_at: row.completed_at ? requireIso(row.completed_at) : null,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
