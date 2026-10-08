/** Project contracts. */
import { z } from 'zod';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export const CreateProjectRequestSchema = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(2000).default(''),
  })
  .strict();
export type CreateProjectRequest = z.infer<typeof CreateProjectRequestSchema>;

export const ProjectSchema = z.object({
  id: IdSchema,
  owner_id: IdSchema,
  name: z.string(),
  description: z.string(),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type Project = z.infer<typeof ProjectSchema>;
