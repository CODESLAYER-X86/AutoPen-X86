/** Target contracts. */
import { z } from 'zod';
import { TARGET_TYPES } from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export const CreateTargetRequestSchema = z
  .object({
    type: z.enum(TARGET_TYPES),
    value: z.string().min(1).max(2048),
    label: z.string().max(200).optional(),
  })
  .strict();
export type CreateTargetRequest = z.infer<typeof CreateTargetRequestSchema>;

export const TargetSchema = z.object({
  id: IdSchema,
  engagement_id: IdSchema,
  type: z.enum(TARGET_TYPES),
  value: z.string(),
  label: z.string().nullable(),
  metadata: z.record(z.unknown()),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type Target = z.infer<typeof TargetSchema>;
