import type { Pool } from 'pg';
import { generateId, type TokenPurpose } from '@aegis/shared';
import type { ModelCallRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const CALL_COLUMNS =
  'id, engagement_id, run_id, task_id, decision_id, role, purpose, provider, model, input_tokens, output_tokens, duration_ms, status, error_code, created_at';

export interface CreateModelCallInput {
  engagementId: string;
  runId: string | null;
  taskId: string | null;
  decisionId: string | null;
  role: 'strategic' | 'tactical';
  purpose: TokenPurpose;
  provider: string;
  model: string;
  inputTokens?: number;
  outputTokens?: number;
  durationMs?: number | null;
  status?: 'COMPLETED' | 'FAILED';
  errorCode?: string | null;
}

export interface TokenUsageByPurpose {
  purpose: TokenPurpose;
  input_tokens: number;
  output_tokens: number;
  calls: number;
}

export interface RecentUsage {
  requests: number;
  inputTokens: number;
  outputTokens: number;
}

export class ModelCallsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateModelCallInput): Promise<ModelCallRecord> {
    const id = generateId('MCL');
    const result = await this.pool.query(
      `INSERT INTO model_calls
         (id, engagement_id, run_id, task_id, decision_id, role, purpose, provider, model,
          input_tokens, output_tokens, duration_ms, status, error_code)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING ${CALL_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.runId,
        input.taskId,
        input.decisionId,
        input.role,
        input.purpose,
        input.provider,
        input.model,
        input.inputTokens ?? 0,
        input.outputTokens ?? 0,
        input.durationMs ?? null,
        input.status ?? 'COMPLETED',
        input.errorCode ?? null,
      ],
    );
    return mapCall(result.rows[0]!);
  }

  /** Usage grouped by purpose (token budget observability, §38). */
  async usageByPurpose(engagementId: string): Promise<TokenUsageByPurpose[]> {
    const result = await this.pool.query<{
      purpose: TokenPurpose;
      input_tokens: number;
      output_tokens: number;
      calls: number;
    }>(
      `SELECT purpose,
              COALESCE(sum(input_tokens), 0)::int AS input_tokens,
              COALESCE(sum(output_tokens), 0)::int AS output_tokens,
              count(*)::int AS calls
       FROM model_calls WHERE engagement_id = $1 GROUP BY purpose`,
      [engagementId],
    );
    return result.rows;
  }

  /**
   * Cross-restart quota accuracy (§37): usage within a recent window.
   * `windowMs` is the sliding window size in milliseconds.
   */
  async recentUsage(engagementId: string, windowMs: number): Promise<RecentUsage> {
    const result = await this.pool.query<{
      requests: number;
      input_tokens: number;
      output_tokens: number;
    }>(
      `SELECT count(*)::int AS requests,
              COALESCE(sum(input_tokens), 0)::int AS input_tokens,
              COALESCE(sum(output_tokens), 0)::int AS output_tokens
       FROM model_calls
       WHERE engagement_id = $1
         AND status = 'COMPLETED'
         AND created_at > now() - ($2::bigint * interval '1 millisecond')`,
      [engagementId, windowMs],
    );
    const row = result.rows[0]!;
    return {
      requests: row.requests,
      inputTokens: row.input_tokens,
      outputTokens: row.output_tokens,
    };
  }

  async totalCalls(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM model_calls WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n;
  }

  async listByRun(runId: string, limit = 200): Promise<ModelCallRecord[]> {
    const result = await this.pool.query(
      `SELECT ${CALL_COLUMNS} FROM model_calls WHERE run_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [runId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapCall);
  }
}

type CallRow = {
  id: string;
  engagement_id: string;
  run_id: string | null;
  task_id: string | null;
  decision_id: string | null;
  role: 'strategic' | 'tactical';
  purpose: TokenPurpose;
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  status: 'COMPLETED' | 'FAILED';
  error_code: string | null;
  created_at: Date;
};

export function mapCall(row: CallRow): ModelCallRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    run_id: row.run_id,
    task_id: row.task_id,
    decision_id: row.decision_id,
    role: row.role,
    purpose: row.purpose,
    provider: row.provider,
    model: row.model,
    input_tokens: row.input_tokens,
    output_tokens: row.output_tokens,
    duration_ms: row.duration_ms,
    status: row.status,
    error_code: row.error_code,
    created_at: requireIso(row.created_at),
  };
}
