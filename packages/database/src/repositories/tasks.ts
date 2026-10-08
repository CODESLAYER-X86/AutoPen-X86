import type { Pool } from 'pg';
import { generateId, type TaskStatus, type TaskType, type WorkerType } from '@aegis/shared';
import type { TaskRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const TASK_COLUMNS =
  'id, engagement_id, run_id, decision_id, hypothesis_id, type, objective, worker_type, status, priority, expected_information_gain, depends_on, allowed_tools, constraints, inputs, result, attempts, max_attempts, failure_code, failure_reason, idempotency_key, created_at, updated_at, started_at, completed_at';

export interface CreateTaskInput {
  engagementId: string;
  runId: string | null;
  decisionId: string | null;
  hypothesisId: string | null;
  type: TaskType;
  objective: string;
  workerType: WorkerType;
  priority: number;
  expectedInformationGain?: number | null;
  dependsOn?: string[];
  allowedTools?: string[];
  constraints?: Record<string, unknown>;
  inputs?: Record<string, unknown>;
  maxAttempts?: number;
  idempotencyKey: string;
}

/** Statuses that mean the task still needs scheduler attention. */
export const PENDING_TASK_STATUSES: readonly TaskStatus[] = [
  'CREATED',
  'QUEUED',
  'READY',
  'RUNNING',
  'WAITING',
  'RECOVERY_PENDING',
];

export class TasksRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /**
   * Idempotent create (spec Part 2 §65): re-creating a task with the same
   * (engagement, idempotency_key) returns the existing row instead of
   * duplicating work.
   */
  async create(input: CreateTaskInput): Promise<TaskRecord> {
    const id = generateId('TSK');
    const result = await this.pool.query(
      `INSERT INTO tasks
         (id, engagement_id, run_id, decision_id, hypothesis_id, type, objective, worker_type,
          status, priority, expected_information_gain, depends_on, allowed_tools, constraints,
          inputs, max_attempts, idempotency_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'QUEUED', $9, $10, $11::jsonb, $12::jsonb,
               $13::jsonb, $14::jsonb, $15, $16)
       ON CONFLICT (engagement_id, idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
       RETURNING ${TASK_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.runId,
        input.decisionId,
        input.hypothesisId,
        input.type,
        input.objective,
        input.workerType,
        input.priority,
        input.expectedInformationGain ?? null,
        JSON.stringify(input.dependsOn ?? []),
        JSON.stringify(input.allowedTools ?? []),
        JSON.stringify(input.constraints ?? {}),
        JSON.stringify(input.inputs ?? {}),
        input.maxAttempts ?? 3,
        input.idempotencyKey,
      ],
    );
    return mapTask(result.rows[0]!);
  }

  async findById(id: string): Promise<TaskRecord | null> {
    const result = await this.pool.query(`SELECT ${TASK_COLUMNS} FROM tasks WHERE id = $1`, [id]);
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  async findByIdAndEngagement(id: string, engagementId: string): Promise<TaskRecord | null> {
    const result = await this.pool.query(
      `SELECT ${TASK_COLUMNS} FROM tasks WHERE id = $1 AND engagement_id = $2`,
      [id, engagementId],
    );
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  /** Deterministic task transitions (Part 2 §18). */
  async updateStatus(id: string, status: TaskStatus): Promise<TaskRecord | null> {
    const result = await this.pool.query(
      `UPDATE tasks SET
         status = $2,
         started_at = CASE WHEN $2 = 'RUNNING' THEN now() ELSE started_at END,
         completed_at = CASE WHEN $2 IN ('COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'EXPIRED')
                            THEN now() ELSE completed_at END,
         updated_at = now()
       WHERE id = $1
       RETURNING ${TASK_COLUMNS}`,
      [id, status],
    );
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  async attachResult(id: string, result: Record<string, unknown>): Promise<TaskRecord | null> {
    const updated = await this.pool.query(
      `UPDATE tasks SET result = $2::jsonb, updated_at = now() WHERE id = $1
       RETURNING ${TASK_COLUMNS}`,
      [id, JSON.stringify(result)],
    );
    return updated.rows[0] ? mapTask(updated.rows[0]) : null;
  }

  async recordFailure(
    id: string,
    code: string | null,
    reason: string | null,
  ): Promise<TaskRecord | null> {
    const result = await this.pool.query(
      `UPDATE tasks SET failure_code = $2, failure_reason = $3, updated_at = now()
       WHERE id = $1 RETURNING ${TASK_COLUMNS}`,
      [id, code, reason],
    );
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  async incrementAttempts(id: string): Promise<TaskRecord | null> {
    const result = await this.pool.query(
      `UPDATE tasks SET attempts = attempts + 1, updated_at = now()
       WHERE id = $1 RETURNING ${TASK_COLUMNS}`,
      [id],
    );
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  /** Anti-loop priority reduction (spec Part 2 §51). */
  async updatePriority(id: string, priority: number): Promise<TaskRecord | null> {
    const result = await this.pool.query(
      `UPDATE tasks SET priority = GREATEST(0, LEAST(1, $2)), updated_at = now()
       WHERE id = $1 RETURNING ${TASK_COLUMNS}`,
      [id, priority],
    );
    return result.rows[0] ? mapTask(result.rows[0]) : null;
  }

  async listByEngagement(
    engagementId: string,
    options: { statuses?: readonly TaskStatus[]; limit?: number } = {},
  ): Promise<TaskRecord[]> {
    const limit = Math.min(Math.max(options.limit ?? 200, 1), 500);
    if (options.statuses && options.statuses.length > 0) {
      const result = await this.pool.query(
        `SELECT ${TASK_COLUMNS} FROM tasks
         WHERE engagement_id = $1 AND status = ANY($2::text[])
         ORDER BY priority DESC, created_at DESC LIMIT $3`,
        [engagementId, [...options.statuses], limit],
      );
      return result.rows.map(mapTask);
    }
    const result = await this.pool.query(
      `SELECT ${TASK_COLUMNS} FROM tasks WHERE engagement_id = $1
       ORDER BY priority DESC, created_at DESC LIMIT $2`,
      [engagementId, limit],
    );
    return result.rows.map(mapTask);
  }

  async listByRun(runId: string): Promise<TaskRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TASK_COLUMNS} FROM tasks WHERE run_id = $1
       ORDER BY priority DESC, created_at DESC`,
      [runId],
    );
    return result.rows.map(mapTask);
  }

  async countByStatus(engagementId: string): Promise<Record<TaskStatus, number>> {
    const result = await this.pool.query<{ status: TaskStatus; n: number }>(
      'SELECT status, count(*)::int AS n FROM tasks WHERE engagement_id = $1 GROUP BY status',
      [engagementId],
    );
    const counts = {
      CREATED: 0,
      QUEUED: 0,
      READY: 0,
      RUNNING: 0,
      WAITING: 0,
      COMPLETED: 0,
      PARTIAL: 0,
      FAILED: 0,
      CANCELLED: 0,
      EXPIRED: 0,
      RECOVERY_PENDING: 0,
    } as Record<TaskStatus, number>;
    for (const row of result.rows) counts[row.status] = row.n;
    return counts;
  }

  /** Tasks found RUNNING during crash recovery (Part 2 §64). */
  async findRunningByEngagement(engagementId: string): Promise<TaskRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TASK_COLUMNS} FROM tasks WHERE engagement_id = $1 AND status = 'RUNNING'`,
      [engagementId],
    );
    return result.rows.map(mapTask);
  }

  async findHanging(engagementId: string, olderThanMs: number): Promise<TaskRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TASK_COLUMNS} FROM tasks
       WHERE engagement_id = $1 AND status IN ('RUNNING', 'READY', 'QUEUED', 'WAITING')
         AND updated_at < now() - ($2::bigint * interval '1 millisecond')`,
      [engagementId, olderThanMs],
    );
    return result.rows.map(mapTask);
  }
}

type TaskRow = {
  id: string;
  engagement_id: string;
  run_id: string | null;
  decision_id: string | null;
  hypothesis_id: string | null;
  type: TaskType;
  objective: string;
  worker_type: WorkerType;
  status: TaskStatus;
  priority: number;
  expected_information_gain: number | null;
  depends_on: string[];
  allowed_tools: string[];
  constraints: Record<string, unknown>;
  inputs: Record<string, unknown>;
  result: Record<string, unknown> | null;
  attempts: number;
  max_attempts: number;
  failure_code: string | null;
  failure_reason: string | null;
  idempotency_key: string;
  created_at: Date;
  updated_at: Date;
  started_at: Date | null;
  completed_at: Date | null;
};

export function mapTask(row: TaskRow): TaskRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    run_id: row.run_id,
    decision_id: row.decision_id,
    hypothesis_id: row.hypothesis_id,
    type: row.type,
    objective: row.objective,
    worker_type: row.worker_type,
    status: row.status,
    priority: row.priority,
    expected_information_gain: row.expected_information_gain,
    depends_on: row.depends_on ?? [],
    allowed_tools: row.allowed_tools ?? [],
    constraints: row.constraints ?? {},
    inputs: row.inputs ?? {},
    result: row.result ?? null,
    attempts: row.attempts,
    max_attempts: row.max_attempts,
    failure_code: row.failure_code,
    failure_reason: row.failure_reason,
    idempotency_key: row.idempotency_key,
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
    started_at: row.started_at ? requireIso(row.started_at) : null,
    completed_at: row.completed_at ? requireIso(row.completed_at) : null,
  };
}
