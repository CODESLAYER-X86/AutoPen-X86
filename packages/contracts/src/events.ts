/** Event system contracts (spec §14). The vocabulary itself lives in
 *  @aegis/shared so every layer shares one source of truth. */
import { z } from 'zod';
import { EVENT_TYPES, type EventType } from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export { EVENT_TYPES };
export type { EventType };

export const EngagementEventSchema = z.object({
  id: IdSchema,
  type: z.enum(EVENT_TYPES),
  engagement_id: IdSchema.nullable(),
  task_id: z.string().nullable(),
  trace_id: z.string().nullable(),
  actor_id: z.string().nullable(),
  payload: z.record(z.unknown()),
  occurred_at: IsoDateTimeSchema,
});
export type EngagementEvent = z.infer<typeof EngagementEventSchema>;

/** Internal event envelope used by the EventBus before persistence. */
export interface PlatformEvent {
  type: EventType;
  engagement_id?: string | null;
  task_id?: string | null;
  trace_id?: string | null;
  actor_id?: string | null;
  payload: Record<string, unknown>;
  occurred_at: string;
}
