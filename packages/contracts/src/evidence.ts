/** Evidence contracts (spec §22). */
import { z } from 'zod';
import { IdSchema, IsoDateTimeSchema } from './common.js';

export const EvidenceSchema = z.object({
  id: IdSchema,
  engagement_id: IdSchema,
  type: z.string().min(1).max(100),
  source: z.string().min(1).max(500),
  /** Opaque reference into object storage; never raw content. */
  content_reference: z.string(),
  sha256: z.string().length(64),
  /** Present when this evidence was derived from another evidence record. */
  parent_id: IdSchema.nullable(),
  task_id: z.string().nullable(),
  metadata: z.record(z.unknown()),
  created_at: IsoDateTimeSchema,
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export const EvidenceVerificationSchema = z.object({
  evidence_id: IdSchema,
  verified: z.boolean(),
  reason: z.string().optional(),
});
