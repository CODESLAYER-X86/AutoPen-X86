/** Identity contracts (spec §13). */
import { z } from 'zod';
import { IDENTITY_TYPES } from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export const CreateIdentityRequestSchema = z
  .object({
    name: z.string().min(1).max(200),
    role: z.string().max(100).default(''),
    type: z.enum(IDENTITY_TYPES),
    metadata: z.record(z.unknown()).default({}),
  })
  .strict();
export type CreateIdentityRequest = z.infer<typeof CreateIdentityRequestSchema>;

export const IdentitySchema = z.object({
  id: IdSchema,
  engagement_id: IdSchema,
  name: z.string(),
  role: z.string(),
  type: z.enum(IDENTITY_TYPES),
  metadata: z.record(z.unknown()),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type Identity = z.infer<typeof IdentitySchema>;
