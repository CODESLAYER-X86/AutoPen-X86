import type { Pool } from 'pg';
import { generateId, type WorkerType } from '@aegis/shared';
import type { TaskAttemptRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const ATTEMPT_COLUMNS =
  'id, task_id, engagement_id, attempt, worker_type, worker_model, status, output, error_code, error_message, tool_calls, network_requests, input_tokens, output_tokens, duration_ms, started_at, ended_at';

export interface CreateAttemptInput {
  taskId: string;
  engagementId: string;
  attempt: number;
  workerType: WorkerType;
  workerModel: string;
}

export interface FinishAttemptInput {
  status: string;
  output?: Record<string, unknown> | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  toolCalls?: number;
  networkRequests?: number;
  inputTokens?: number;
  outputTokens?: number;
  durationMs?: number | null;
}

export class TaskAttemptsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAttemptInput): Promise<TaskAttemptRecord> {
    const id = generateId('ATT');
    const result = await this.pool.query(
      `INSERT INTO task_attempts (id, task_id, engagement_id, attempt, worker_type, worker_model, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'RUNNING')
       RETURNING ${ATTEMPT_COLUMNS}`,
      [id, input.taskId, input.engagementId, input.attempt, input.workerType, input.workerModel],
    );
    return mapAttempt(result.rows[0]!);
  }

  async finish(id: string, input: FinishAttemptInput): Promise<TaskAttemptRecord | null> {
    const result = await this.pool.query(
      `UPDATE task_attempts SET
         status = $2,
         output = COALESCE($3::jsonb, output),
         error_code = $4,
         error_message = $5,
         tool_calls = $6,
         network_requests = $7,
         input_tokens = $8,
         output_tokens = $9,
         duration_ms = $10,
         ended_at = now()
       WHERE id = $1
       RETURNING ${ATTEMPT_COLUMNS}`,
      [
        id,
        input.status,
        input.output ? JSON.stringify(input.output) : null,
        input.errorCode ?? null,
        input.errorMessage ?? null,
        input.toolCalls ?? 0,
        input.networkRequests ?? 0,
        input.inputTokens ?? 0,
        input.outputTokens ?? 0,
        input.durationMs ?? null,
      ],
    );
    return result.rows[0] ? mapAttempt(result.rows[0]) : null;
  }

  async listByTask(taskId: string): Promise<TaskAttemptRecord[]> {
    const result = await this.pool.query(
      `SELECT ${ATTEMPT_COLUMNS} FROM task_attempts WHERE task_id = $1 ORDER BY attempt DESC`,
      [taskId],
    );
    return result.rows.map(mapAttempt);
  }

  async findById(id: string): Promise<TaskAttemptRecord | null> {
    const result = await this.pool.query(
      `SELECT ${ATTEMPT_COLUMNS} FROM task_attempts WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapAttempt(result.rows[0]) : null;
  }

  async countWorkerFailures(engagementId: string, workerType: WorkerType): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM task_attempts
       WHERE engagement_id = $1 AND worker_type = $2 AND status = 'FAILED'`,
      [engagementId, workerType],
    );
    return result.rows[0]!.n;
  }
}

type AttemptRow = {
  id: string;
  task_id: string;
  engagement_id: string;
  attempt: number;
  worker_type: WorkerType;
  worker_model: string;
  status: string;
  output: Record<string, unknown> | null;
  error_code: string | null;
  error_message: string | null;
  tool_calls: number;
  network_requests: number;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  started_at: Date;
  ended_at: Date | null;
};

export function mapAttempt(row: AttemptRow): TaskAttemptRecord {
  return {
    id: row.id,
    task_id: row.task_id,
    engagement_id: row.engagement_id,
    attempt: row.attempt,
    worker_type: row.worker_type,
    worker_model: row.worker_model,
    status: row.status,
    output: row.output ?? null,
    error_code: row.error_code,
    error_message: row.error_message,
    tool_calls: row.tool_calls,
    network_requests: row.network_requests,
    input_tokens: row.input_tokens,
    output_tokens: row.output_tokens,
    duration_ms: row.duration_ms,
    started_at: requireIso(row.started_at),
    ended_at: row.ended_at ? requireIso(row.ended_at) : null,
  };
}
