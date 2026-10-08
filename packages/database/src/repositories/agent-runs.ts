import type { Pool } from 'pg';
import { generateId, type AgentRunStatus } from '@aegis/shared';
import type { AgentRunRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const RUN_COLUMNS =
  'id, engagement_id, status, reason, strategy_version, leader_model, worker_model, metrics, started_at, ended_at, created_at, updated_at';

export interface CreateAgentRunInput {
  engagementId: string;
  leaderModel: string;
  workerModel: string;
  reason: string | null;
}

/** Statuses that mean "this run owns the engagement's autonomous activity". */
export const ACTIVE_RUN_STATUSES: readonly AgentRunStatus[] = [
  'CREATED',
  'INITIALIZING',
  'RUNNING',
  'WAITING',
  'PAUSED',
];

export class AgentRunsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAgentRunInput): Promise<AgentRunRecord> {
    const id = generateId('RUN');
    const result = await this.pool.query(
      `INSERT INTO agent_runs (id, engagement_id, leader_model, worker_model, reason)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING ${RUN_COLUMNS}`,
      [id, input.engagementId, input.leaderModel, input.workerModel, input.reason],
    );
    return mapRun(result.rows[0]!);
  }

  async findById(id: string): Promise<AgentRunRecord | null> {
    const result = await this.pool.query(
      `SELECT ${RUN_COLUMNS} FROM agent_runs WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async findActiveByEngagement(engagementId: string): Promise<AgentRunRecord | null> {
    const result = await this.pool.query(
      `SELECT ${RUN_COLUMNS} FROM agent_runs
       WHERE engagement_id = $1 AND status = ANY($2::text[])
       ORDER BY created_at DESC LIMIT 1`,
      [engagementId, [...ACTIVE_RUN_STATUSES]],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<AgentRunRecord[]> {
    const result = await this.pool.query(
      `SELECT ${RUN_COLUMNS} FROM agent_runs WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapRun);
  }

  /** Deterministic single write path for run transitions (Part 2 §3). */
  async updateStatus(id: string, status: AgentRunStatus): Promise<AgentRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_runs SET
         status = $2,
         started_at = CASE WHEN $2 IN ('INITIALIZING', 'RUNNING', 'WAITING') AND started_at IS NULL THEN now() ELSE started_at END,
         ended_at = CASE WHEN $2 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN now() ELSE ended_at END,
         updated_at = now()
       WHERE id = $1
       RETURNING ${RUN_COLUMNS}`,
      [id, status],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  /** Shallow-merges metrics into the run's metrics JSON (Part 2 §58). */
  async updateMetrics(id: string, metrics: Record<string, unknown>): Promise<AgentRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_runs SET
         metrics = metrics || $2::jsonb,
         updated_at = now()
       WHERE id = $1
       RETURNING ${RUN_COLUMNS}`,
      [id, JSON.stringify(metrics)],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }

  async updateStrategyVersion(id: string, version: number): Promise<AgentRunRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_runs SET strategy_version = $2, updated_at = now()
       WHERE id = $1 RETURNING ${RUN_COLUMNS}`,
      [id, version],
    );
    return result.rows[0] ? mapRun(result.rows[0]) : null;
  }
}

type RunRow = {
  id: string;
  engagement_id: string;
  status: AgentRunStatus;
  reason: string | null;
  strategy_version: number | null;
  leader_model: string;
  worker_model: string;
  metrics: Record<string, unknown>;
  started_at: Date | null;
  ended_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

export function mapRun(row: RunRow): AgentRunRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    status: row.status,
    reason: row.reason,
    strategy_version: row.strategy_version,
    leader_model: row.leader_model,
    worker_model: row.worker_model,
    metrics: row.metrics ?? {},
    started_at: row.started_at ? requireIso(row.started_at) : null,
    ended_at: row.ended_at ? requireIso(row.ended_at) : null,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}
