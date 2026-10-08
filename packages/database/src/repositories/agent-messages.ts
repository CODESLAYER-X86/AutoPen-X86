import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type { AgentMessageRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const MESSAGE_COLUMNS =
  'id, engagement_id, run_id, task_id, channel, direction, role, content, untrusted_bytes, metadata, input_tokens, output_tokens, created_at';

export interface CreateAgentMessageInput {
  engagementId: string;
  runId: string | null;
  taskId: string | null;
  channel: 'LEADER' | 'WORKER';
  direction: 'OUTBOUND' | 'INBOUND';
  role: 'system' | 'user' | 'assistant';
  content: string;
  untrustedBytes?: number;
  metadata?: Record<string, unknown>;
  inputTokens?: number | null;
  outputTokens?: number | null;
}

export class AgentMessagesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async create(input: CreateAgentMessageInput): Promise<AgentMessageRecord> {
    const id = generateId('MSG');
    const result = await this.pool.query(
      `INSERT INTO agent_messages
         (id, engagement_id, run_id, task_id, channel, direction, role, content, untrusted_bytes,
          metadata, input_tokens, output_tokens)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12)
       RETURNING ${MESSAGE_COLUMNS}`,
      [
        id,
        input.engagementId,
        input.runId,
        input.taskId,
        input.channel,
        input.direction,
        input.role,
        input.content,
        input.untrustedBytes ?? 0,
        JSON.stringify(input.metadata ?? {}),
        input.inputTokens ?? null,
        input.outputTokens ?? null,
      ],
    );
    return mapMessage(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<AgentMessageRecord[]> {
    const result = await this.pool.query(
      `SELECT ${MESSAGE_COLUMNS} FROM agent_messages WHERE engagement_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapMessage);
  }

  async listByRun(runId: string, limit = 100): Promise<AgentMessageRecord[]> {
    const result = await this.pool.query(
      `SELECT ${MESSAGE_COLUMNS} FROM agent_messages WHERE run_id = $1
       ORDER BY created_at DESC LIMIT $2`,
      [runId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapMessage);
  }
}

type MessageRow = {
  id: string;
  engagement_id: string;
  run_id: string | null;
  task_id: string | null;
  channel: 'LEADER' | 'WORKER';
  direction: 'OUTBOUND' | 'INBOUND';
  role: 'system' | 'user' | 'assistant';
  content: string;
  untrusted_bytes: number;
  metadata: Record<string, unknown>;
  input_tokens: number | null;
  output_tokens: number | null;
  created_at: Date;
};

export function mapMessage(row: MessageRow): AgentMessageRecord {
  return {
    id: row.id,
    engagement_id: row.engagement_id,
    run_id: row.run_id,
    task_id: row.task_id,
    channel: row.channel,
    direction: row.direction,
    role: row.role,
    content: row.content,
    untrusted_bytes: row.untrusted_bytes,
    metadata: row.metadata ?? {},
    input_tokens: row.input_tokens,
    output_tokens: row.output_tokens,
    created_at: requireIso(row.created_at),
  };
}
