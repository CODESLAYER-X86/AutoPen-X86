import type { Pool } from 'pg';
import { generateId, type TestResultOutcome, type TestStatus } from '@aegis/shared';
import type { TestRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const TEST_COLUMNS =
  'id, engagement_id, task_id, hypothesis_id, test_type, target, identity, mutation_summary, fingerprint, status, result_summary, result, expected_signal, actual_signal, mutation, created_at';

export interface CreateTestInput {
  engagementId: string;
  taskId: string | null;
  hypothesisId: string | null;
  testType: string;
  target: string;
  identity?: string | null;
  mutationSummary?: string | null;
  fingerprint: string;
  /** Part 6 §60: expected/actual signal + structural mutation record. */
  expectedSignal?: string | null;
  mutation?: Record<string, unknown> | null;
}

export interface CreateTestResult {
  record: TestRecord;
  /** True when the fingerprint already existed (duplicate detection, §29). */
  duplicate: boolean;
}

export class TestsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /**
   * Registers a test. Duplicate fingerprints return the existing record
   * flagged as duplicate — the scheduler uses this to avoid double work
   * (spec Part 2 §28-§29).
   */
  async register(input: CreateTestInput): Promise<CreateTestResult> {
    const id = generateId('TST');
    const result = await this.pool.query(
      `INSERT INTO tests
         (id, engagement_id, task_id, hypothesis_id, test_type, target, identity, mutation_summary,
          fingerprint, expected_signal, mutation)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
       ON CONFLICT (engagement_id, fingerprint) DO UPDATE SET fingerprint = EXCLUDED.fingerprint
       RETURNING ${TEST_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.taskId,
        input.hypothesisId,
        input.testType,
        input.target,
        input.identity ?? null,
        input.mutationSummary ?? null,
        input.fingerprint,
        input.expectedSignal ?? null,
        JSON.stringify(input.mutation ?? null),
      ],
    );
    const row = result.rows[0]!;
    // If the returned id differs from the id we tried to insert, the unique
    // fingerprint constraint fired and the existing row was returned.
    return { record: mapTest(row), duplicate: row.id !== id };
  }

  async markDuplicate(fingerprint: string, engagementId: string): Promise<void> {
    await this.pool.query(
      `UPDATE tests SET status = 'DUPLICATE' WHERE engagement_id = $1 AND fingerprint = $2`,
      [engagementId, fingerprint],
    );
  }

  async findByFingerprint(engagementId: string, fingerprint: string): Promise<TestRecord | null> {
    const result = await this.pool.query(
      `SELECT ${TEST_COLUMNS} FROM tests WHERE engagement_id = $1 AND fingerprint = $2`,
      [engagementId, fingerprint],
    );
    return result.rows[0] ? mapTest(result.rows[0]) : null;
  }

  async updateResult(
    id: string,
    status: TestStatus,
    resultSummary: string,
  ): Promise<TestRecord | null> {
    const result = await this.pool.query(
      `UPDATE tests SET status = $2, result_summary = $3 WHERE id = $1
       RETURNING ${TEST_COLUMNS}`,
      [id, status, resultSummary],
    );
    return result.rows[0] ? mapTest(result.rows[0]) : null;
  }

  /**
   * Part 6 §60: record the experimental verdict — what the test concluded
   * about its hypothesis (SUPPORTED / DISPROVED / INCONCLUSIVE / BLOCKED /
   * FAILED) plus the observed signal. This is the agent's experimental memory.
   */
  async recordOutcome(
    id: string,
    outcome: TestResultOutcome,
    actualSignal: string | null,
  ): Promise<TestRecord | null> {
    const result = await this.pool.query(
      `UPDATE tests SET result = $2, actual_signal = $3 WHERE id = $1
       RETURNING ${TEST_COLUMNS}`,
      [id, outcome, actualSignal],
    );
    return result.rows[0] ? mapTest(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<TestRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TEST_COLUMNS} FROM tests WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapTest);
  }

  async countByEngagement(engagementId: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM tests WHERE engagement_id = $1',
      [engagementId],
    );
    return result.rows[0]!.n;
  }
}

type TestRow = {
  id: string;
  engagement_id: string;
  task_id: string | null;
  hypothesis_id: string | null;
  test_type: string;
  target: string;
  identity: string | null;
  mutation_summary: string | null;
  fingerprint: string;
  status: TestStatus;
  result_summary: string | null;
  result: TestResultOutcome | null;
  expected_signal: string | null;
  actual_signal: string | null;
  mutation: Record<string, unknown> | null;
  created_at: Date;
};

export function mapTest(row: TestRow): TestRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    task_id: row.task_id,
    hypothesis_id: row.hypothesis_id,
    test_type: row.test_type,
    target: row.target,
    identity: row.identity,
    mutation_summary: row.mutation_summary,
    fingerprint: row.fingerprint,
    status: row.status,
    result_summary: row.result_summary,
    result: row.result,
    expected_signal: row.expected_signal,
    actual_signal: row.actual_signal,
    mutation: row.mutation,
    created_at: requireIso(row.created_at),
  };
}
