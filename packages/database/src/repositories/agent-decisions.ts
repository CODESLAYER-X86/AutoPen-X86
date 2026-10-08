import type { Pool } from 'pg';
import { generateId, type DecisionType } from '@aegis/shared';
import type { AgentDecisionRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const DECISION_COLUMNS =
  'id, run_id, engagement_id, cycle, input_state_hash, decision_type, reasoning_summary, payload, validation_status, rejection_code, rejection_details, cycle_outcome, input_tokens, output_tokens, duration_ms, created_at';

export interface CreateDecisionInput {
  runId: string;
  engagementId: string;
  cycle: number;
  inputStateHash: string;
  decisionType: DecisionType;
  reasoningSummary: string;
  payload: Record<string, unknown>;
  inputTokens?: number;
  outputTokens?: number;
  durationMs?: number;
}

export class AgentDecisionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateDecisionInput): Promise<AgentDecisionRecord> {
    const id = generateId('DCS');
    const result = await this.pool.query(
      `INSERT INTO agent_decisions
         (id, run_id, engagement_id, cycle, input_state_hash, decision_type,
          reasoning_summary, payload, validation_status, input_tokens, output_tokens, duration_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'PENDING', $9, $10, $11)
       RETURNING ${DECISION_COLUMNS}`,
      [
        id,
        input.runId,
        input.engagementId,
        input.cycle,
        input.inputStateHash,
        input.decisionType,
        input.reasoningSummary,
        JSON.stringify(input.payload),
        input.inputTokens ?? 0,
        input.outputTokens ?? 0,
        input.durationMs ?? null,
      ],
    );
    return mapDecision(result.rows[0]!);
  }

  async markValid(id: string): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_decisions SET validation_status = 'VALID' WHERE id = $1
       RETURNING ${DECISION_COLUMNS}`,
      [id],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  async markRejected(
    id: string,
    code: string,
    details: Record<string, unknown>,
  ): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_decisions SET
         validation_status = 'REJECTED', rejection_code = $2, rejection_details = $3::jsonb
       WHERE id = $1
       RETURNING ${DECISION_COLUMNS}`,
      [id, code, JSON.stringify(details)],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  async markFailed(id: string, code: string, details: Record<string, unknown>): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_decisions SET
         validation_status = 'FAILED', rejection_code = $2, rejection_details = $3::jsonb
       WHERE id = $1
       RETURNING ${DECISION_COLUMNS}`,
      [id, code, JSON.stringify(details)],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  /** Records the decision-cycle outcome (spec Part 2 §31). */
  async recordOutcome(
    id: string,
    outcome: Record<string, unknown>,
  ): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_decisions SET cycle_outcome = $2::jsonb WHERE id = $1
       RETURNING ${DECISION_COLUMNS}`,
      [id, JSON.stringify(outcome)],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  async recordUsage(
    id: string,
    usage: { inputTokens: number; outputTokens: number; durationMs?: number },
  ): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `UPDATE agent_decisions SET
         input_tokens = $2, output_tokens = $3,
         duration_ms = COALESCE($4, duration_ms)
       WHERE id = $1
       RETURNING ${DECISION_COLUMNS}`,
      [id, usage.inputTokens, usage.outputTokens, usage.durationMs ?? null],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  async nextCycle(runId: string): Promise<number> {
    const result = await this.pool.query<{ max_cycle: number | null }>(
      'SELECT max(cycle) AS max_cycle FROM agent_decisions WHERE run_id = $1',
      [runId],
    );
    return (result.rows[0]?.max_cycle ?? 0) + 1;
  }

  async findById(id: string): Promise<AgentDecisionRecord | null> {
    const result = await this.pool.query(
      `SELECT ${DECISION_COLUMNS} FROM agent_decisions WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapDecision(result.rows[0]) : null;
  }

  async listByRun(runId: string, limit = 100): Promise<AgentDecisionRecord[]> {
    const result = await this.pool.query(
      `SELECT ${DECISION_COLUMNS} FROM agent_decisions WHERE run_id = $1
       ORDER BY cycle DESC LIMIT $2`,
      [runId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapDecision);
  }
}

type DecisionRow = {
  id: string;
  run_id: string;
  engagement_id: string;
  cycle: number;
  input_state_hash: string;
  decision_type: DecisionType;
  reasoning_summary: string;
  payload: Record<string, unknown>;
  validation_status: AgentDecisionRecord['validation_status'];
  rejection_code: string | null;
  rejection_details: Record<string, unknown> | null;
  cycle_outcome: Record<string, unknown> | null;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  created_at: Date;
};

export function mapDecision(row: DecisionRow): AgentDecisionRecord {
  return {
    id: row.id,
    run_id: row.run_id,
    engagement_id: row.engagement_id,
    cycle: row.cycle,
    input_state_hash: row.input_state_hash,
    decision_type: row.decision_type,
    reasoning_summary: row.reasoning_summary,
    payload: row.payload ?? {},
    validation_status: row.validation_status,
    rejection_code: row.rejection_code,
    rejection_details: row.rejection_details ?? null,
    cycle_outcome: row.cycle_outcome ?? null,
    input_tokens: row.input_tokens,
    output_tokens: row.output_tokens,
    duration_ms: row.duration_ms,
    created_at: requireIso(row.created_at),
  };
}
