/** Scope contracts (spec §10). */
import { z } from 'zod';
import { IdSchema, IsoDateTimeSchema } from './common.js';

const hostEntry = z
  .string()
  .min(1)
  .max(253)
  .regex(/^[a-z0-9.\-_\[\]:]+$/i, 'Invalid host entry');

const pathEntry = z
  .string()
  .min(1)
  .max(1024)
  .refine((v) => v.startsWith('/') || !v.includes('://'), 'Path entries must be absolute paths');

export const ScopeRequestSchema = z
  .object({
    allowed_hosts: z.array(hostEntry).max(100).default([]),
    allowed_domains: z.array(hostEntry).max(100).default([]),
    allowed_ports: z.array(z.number().int().min(1).max(65535)).max(100).default([]),
    allowed_schemes: z
      .array(z.enum(['http', 'https', 'ws', 'wss']))
      .min(1, 'At least one allowed scheme is required'),
    excluded_hosts: z.array(hostEntry).max(100).default([]),
    excluded_paths: z.array(pathEntry).max(100).default([]),
    rate_limit: z.number().int().min(1).max(10_000).nullable().optional(),
    concurrency_limit: z.number().int().min(1).max(1000).nullable().optional(),
    destructive_actions_allowed: z.boolean().default(false),
  })
  .strict()
  .refine(
    (data) => data.allowed_hosts.length + data.allowed_domains.length >= 1,
    'At least one allowed host or allowed domain is required — an empty allowlist permits nothing',
  );
export type ScopeRequest = z.infer<typeof ScopeRequestSchema>;

export const ScopeSchema = z.object({
  id: IdSchema,
  engagement_id: IdSchema,
  allowed_hosts: z.array(z.string()),
  allowed_domains: z.array(z.string()),
  allowed_ports: z.array(z.number().int()),
  allowed_schemes: z.array(z.string()),
  excluded_hosts: z.array(z.string()),
  excluded_paths: z.array(z.string()),
  rate_limit: z.number().int().nullable(),
  concurrency_limit: z.number().int().nullable(),
  destructive_actions_allowed: z.boolean(),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type Scope = z.infer<typeof ScopeSchema>;

/** GET /api/engagements/:id/scope returns `{ scope: null }` until configured. */
export const ScopeResponseSchema = z.object({ scope: ScopeSchema.nullable() });
