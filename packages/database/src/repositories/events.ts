import type { Pool } from 'pg';
import { generateId, type EventType } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

export class EventsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(event: PlatformEvent): Promise<EventRecord> {
    const id = generateId('EVT');
    const result = await this.pool.query(
      `INSERT INTO events (id, type, engagement_id, task_id, trace_id, actor_id, payload, occurred_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, COALESCE($8::timestamptz, now()))
       RETURNING id, type, engagement_id, task_id, trace_id, actor_id, payload, occurred_at`,
      [
        id,
        event.type,
        event.engagement_id ?? null,
        event.task_id ?? null,
        event.trace_id ?? null,
        event.actor_id ?? null,
        JSON.stringify(event.payload ?? {}),
        event.occurred_at ?? null,
      ],
    );
    return mapEvent(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<EventRecord[]> {
    const result = await this.pool.query(
      `SELECT id, type, engagement_id, task_id, trace_id, actor_id, payload, occurred_at
       FROM events WHERE engagement_id = $1
       ORDER BY occurred_at DESC, id DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapEvent);
  }
}

type EventRow = {
  id: string;
  type: EventType;
  engagement_id: string | null;
  task_id: string | null;
  trace_id: string | null;
  actor_id: string | null;
  payload: Record<string, unknown>;
  occurred_at: Date;
};

export function mapEvent(row: EventRow): EventRecord {
  return {
    id: row.id,
    type: row.type,
    engagement_id: row.engagement_id,
    task_id: row.task_id,
    trace_id: row.trace_id,
    actor_id: row.actor_id,
    payload: row.payload ?? {},
    occurred_at: requireIso(row.occurred_at),
  };
}
