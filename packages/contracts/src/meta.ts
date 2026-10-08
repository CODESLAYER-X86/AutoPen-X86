/** /api/meta contracts — non-sensitive runtime information. */
import { z } from 'zod';
import { ENGAGEMENT_MODES, PLATFORM_NAME, PLATFORM_VERSION } from '@aegis/shared';

export const MetaResponseSchema = z.object({
  name: z.literal(PLATFORM_NAME),
  version: z.literal(PLATFORM_VERSION),
  environment: z.enum(['development', 'test', 'production']),
  modes: z.array(z.enum(ENGAGEMENT_MODES)),
  models: z.object({
    strategic: z.object({ provider: z.string(), model_id: z.string() }),
    tactical: z.object({ provider: z.string(), model_id: z.string() }),
    google_api_key_configured: z.boolean(),
  }),
  features: z.object({
    tools_http: z.boolean(),
    tools_browser: z.boolean(),
    knowledge_search: z.boolean(),
    reporting: z.boolean(),
  }),
  capabilities: z.object({
    tools_total: z.number().int(),
    tools_implemented: z.number().int(),
    autonomous_run_loop: z.boolean(),
    /** Part 2: which tactical tool families are actually implemented. */
    autonomous_tools: z.object({
      http: z.boolean(),
      browser: z.boolean(),
      knowledge: z.boolean(),
    }),
  }),
});
export type MetaResponse = z.infer<typeof MetaResponseSchema>;
