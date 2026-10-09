import type { Pool } from 'pg';
import { generateId, type EventType } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventRecord } from '../types.js';
import { requireIso, type RepoBase } from './util.js';

const EVENT_COLUMNS =
  'id, type, engagement_id, task_id, trace_id, actor_id, payload, occurred_at, dedup_key';

export class EventsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /**
   * Inserts an event. When the event carries a dedup_key and that key already
   * exists, the insert is a no-op (idempotency, spec Part 2 §65) and the
   * existing row is returned.
   */
  async insert(event: PlatformEvent): Promise<EventRecord> {
    const id = generateId('EVT');
    const dedupKey = event.dedup_key ?? null;
    const result = await this.pool.query(
      `INSERT INTO events (id, type, engagement_id, task_id, trace_id, actor_id, payload, occurred_at, dedup_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, COALESCE($8::timestamptz, now()), $9)
       ON CONFLICT (dedup_key) DO UPDATE SET dedup_key = EXCLUDED.dedup_key
       RETURNING ${EVENT_COLUMNS}`,
      [
        id,
        event.type,
        event.engagement_id ?? null,
        event.task_id ?? null,
        event.trace_id ?? null,
        event.actor_id ?? null,
        JSON.stringify(event.payload ?? {}),
        event.occurred_at ?? null,
        dedupKey,
      ],
    );
    return mapEvent(result.rows[0]!);
  }

  async listByEngagement(engagementId: string, limit = 100): Promise<EventRecord[]> {
    const result = await this.pool.query(
      `SELECT ${EVENT_COLUMNS}
       FROM events WHERE engagement_id = $1
       ORDER BY occurred_at DESC, id DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapEvent);
  }

  /**
   * Part 8 §59: retention sweep for the engagement event log. Bounded batch
   * delete; returns the number of rows removed.
   */
  async deleteOlderThan(days: number, limit: number): Promise<number> {
    const result = await this.pool.query(
      `DELETE FROM events WHERE id IN (
         SELECT id FROM events WHERE occurred_at < now() - ($1 || ' days')::interval LIMIT $2
       )`,
      [String(days), Math.min(Math.max(limit, 1), 5000)],
    );
    return result.rowCount ?? 0;
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
  dedup_key: string | null;
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
    dedup_key: row.dedup_key ?? null,
  };
}
