import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { EngagementBudgetRecord, EngagementUsageRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const BUDGET_COLUMNS =
  'id, engagement_id, max_duration_seconds, max_network_requests, max_concurrent_requests, max_browser_contexts, max_model_calls, max_model_tokens, max_storage_bytes, created_at, updated_at';

export interface BudgetDefaults {
  maxDurationSeconds?: number | null;
  maxNetworkRequests?: number | null;
  maxConcurrentRequests?: number | null;
  maxBrowserContexts?: number | null;
  maxModelCalls?: number | null;
  maxModelTokens?: number | null;
  maxStorageBytes?: number | null;
}

export interface UsageIncrement {
  networkRequests?: number;
  browserContexts?: number;
  modelCalls?: number;
  inputTokens?: number;
  outputTokens?: number;
  storageBytes?: number;
  toolCalls?: number;
}

export class EngagementBudgetsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /** Reads the engagement budget, creating one from defaults if absent. */
  async getOrDefault(engagementId: string, defaults: BudgetDefaults): Promise<EngagementBudgetRecord> {
    const existing = await this.findByEngagement(engagementId);
    if (existing) return existing;

    const id = generateId('BGT');
    const result = await this.pool.query(
      `INSERT INTO engagement_budgets
         (id, engagement_id, max_duration_seconds, max_network_requests, max_concurrent_requests,
          max_browser_contexts, max_model_calls, max_model_tokens, max_storage_bytes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (engagement_id) DO UPDATE SET engagement_id = EXCLUDED.engagement_id
       RETURNING ${BUDGET_COLUMNS}`,
      [
        id,
        engagementId,
        defaults.maxDurationSeconds ?? null,
        defaults.maxNetworkRequests ?? null,
        defaults.maxConcurrentRequests ?? null,
        defaults.maxBrowserContexts ?? null,
        defaults.maxModelCalls ?? null,
        defaults.maxModelTokens ?? null,
        defaults.maxStorageBytes ?? null,
      ],
    );
    return mapBudget(result.rows[0]!);
  }

  async findByEngagement(engagementId: string): Promise<EngagementBudgetRecord | null> {
    const result = await this.pool.query(
      `SELECT ${BUDGET_COLUMNS} FROM engagement_budgets WHERE engagement_id = $1`,
      [engagementId],
    );
    return result.rows[0] ? mapBudget(result.rows[0]) : null;
  }

  async getUsage(engagementId: string): Promise<EngagementUsageRecord> {
    const result = await this.pool.query(
      `SELECT engagement_id, network_requests, concurrent_requests, browser_contexts, model_calls,
              input_tokens, output_tokens, storage_bytes, tool_calls, updated_at
       FROM engagement_usage WHERE engagement_id = $1`,
      [engagementId],
    );
    if (result.rows[0]) return mapUsage(result.rows[0]);
    const empty = await this.pool.query(
      `INSERT INTO engagement_usage (engagement_id) VALUES ($1)
       ON CONFLICT (engagement_id) DO NOTHING
       RETURNING engagement_id, network_requests, concurrent_requests, browser_contexts, model_calls,
                 input_tokens, output_tokens, storage_bytes, tool_calls, updated_at`,
      [engagementId],
    );
    return mapUsage(empty.rows[0]!);
  }

  /** Atomic counter increments (never read-modify-write). */
  async incrementUsage(engagementId: string, increment: UsageIncrement): Promise<EngagementUsageRecord> {
    await this.getUsage(engagementId); // ensure row exists
    const result = await this.pool.query(
      `UPDATE engagement_usage SET
         network_requests = network_requests + $2,
         browser_contexts = browser_contexts + $3,
         model_calls = model_calls + $4,
         input_tokens = input_tokens + $5,
         output_tokens = output_tokens + $6,
         storage_bytes = storage_bytes + $7,
         tool_calls = tool_calls + $8,
         updated_at = now()
       WHERE engagement_id = $1
       RETURNING engagement_id, network_requests, concurrent_requests, browser_contexts, model_calls,
                 input_tokens, output_tokens, storage_bytes, tool_calls, updated_at`,
      [
        engagementId,
        increment.networkRequests ?? 0,
        increment.browserContexts ?? 0,
        increment.modelCalls ?? 0,
        increment.inputTokens ?? 0,
        increment.outputTokens ?? 0,
        increment.storageBytes ?? 0,
        increment.toolCalls ?? 0,
      ],
    );
    return mapUsage(result.rows[0]!);
  }

  async updateConcurrent(engagementId: string, delta: number): Promise<number> {
    const result = await this.pool.query<{ concurrent_requests: number }>(
      `UPDATE engagement_usage SET
         concurrent_requests = GREATEST(0, concurrent_requests + $2),
         updated_at = now()
       WHERE engagement_id = $1
       RETURNING concurrent_requests`,
      [engagementId, delta],
    );
    return result.rows[0]?.concurrent_requests ?? 0;
  }
}

type BudgetRow = {
  id: string;
  engagement_id: string;
  max_duration_seconds: number | null;
  max_network_requests: number | null;
  max_concurrent_requests: number | null;
  max_browser_contexts: number | null;
  max_model_calls: number | null;
  max_model_tokens: number | null;
  max_storage_bytes: string | number | null;
  created_at: Date;
  updated_at: Date;
};

export function mapBudget(row: BudgetRow): EngagementBudgetRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    max_duration_seconds: row.max_duration_seconds,
    max_network_requests: row.max_network_requests,
    max_concurrent_requests: row.max_concurrent_requests,
    max_browser_contexts: row.max_browser_contexts,
    max_model_calls: row.max_model_calls,
    max_model_tokens: row.max_model_tokens,
    max_storage_bytes: row.max_storage_bytes === null ? null : Number(row.max_storage_bytes),
    created_at: requireIso(row.created_at),
    updated_at: requireIso(row.updated_at),
  };
}

type UsageRow = {
  engagement_id: string;
  network_requests: number;
  concurrent_requests: number;
  browser_contexts: number;
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  storage_bytes: string | number;
  tool_calls: number;
  updated_at: Date;
};

export function mapUsage(row: UsageRow): EngagementUsageRecord {
  return {
    engagement_id: row.engagement_id,
    network_requests: row.network_requests,
    concurrent_requests: row.concurrent_requests,
    browser_contexts: row.browser_contexts,
    model_calls: row.model_calls,
    input_tokens: row.input_tokens,
    output_tokens: row.output_tokens,
    storage_bytes: Number(row.storage_bytes),
    tool_calls: row.tool_calls,
    updated_at: requireIso(row.updated_at),
  };
}
