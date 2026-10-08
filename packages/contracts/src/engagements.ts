/** Engagement contracts (mode, lifecycle states, readiness). */
import { z } from 'zod';
import { ENGAGEMENT_MODES, ENGAGEMENT_STATUSES } from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export const CreateEngagementRequestSchema = z
  .object({
    project_id: IdSchema,
    name: z.string().min(1).max(200),
    mode: z.enum(ENGAGEMENT_MODES),
    description: z.string().max(4000).default(''),
  })
  .strict();
export type CreateEngagementRequest = z.infer<typeof CreateEngagementRequestSchema>;

export const EngagementSchema = z.object({
  id: IdSchema,
  project_id: IdSchema,
  name: z.string(),
  mode: z.enum(ENGAGEMENT_MODES),
  status: z.enum(ENGAGEMENT_STATUSES),
  description: z.string(),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
  started_at: IsoDateTimeSchema.nullable(),
  completed_at: IsoDateTimeSchema.nullable(),
});
export type Engagement = z.infer<typeof EngagementSchema>;

export const UpdateEngagementRequestSchema = z
  .object({
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(4000).optional(),
    status: z.enum(ENGAGEMENT_STATUSES).optional(),
  })
  .strict();
export type UpdateEngagementRequest = z.infer<typeof UpdateEngagementRequestSchema>;

/** Readiness signals used by the UI and the lifecycle preconditions. */
export const EngagementReadinessSchema = z.object({
  has_scope: z.boolean(),
  has_targets: z.boolean(),
  ready: z.boolean(),
});
export type EngagementReadiness = z.infer<typeof EngagementReadinessSchema>;

export const EngagementDetailSchema = z.object({
  engagement: EngagementSchema,
  readiness: EngagementReadinessSchema,
});
export type EngagementDetail = z.infer<typeof EngagementDetailSchema>;
