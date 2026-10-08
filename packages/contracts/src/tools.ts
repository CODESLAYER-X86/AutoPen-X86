/** Tool registry contracts (spec §16, §17). */
import { z } from 'zod';
import { RISK_LEVELS, TOOL_CAPABILITIES } from '@aegis/shared';

export const ToolDescriptorSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/, 'Tool names are dotted, lowercase'),
  version: z.string().regex(/^\d+\.\d+\.\d+$/, 'Semantic version'),
  description: z.string().min(1).max(2000),
  risk_level: z.enum(RISK_LEVELS),
  capabilities: z.array(z.enum(TOOL_CAPABILITIES)).min(1),
  requires_scope: z.boolean(),
  requires_identity: z.boolean(),
  /** false = explicitly not implemented yet (surfaced in UI/API). */
  implemented: z.boolean(),
  /** Which later implementation part provides this tool, when not implemented. */
  planned_part: z.string().optional(),
});
export type ToolDescriptor = z.infer<typeof ToolDescriptorSchema>;

export const ToolExecutionResultSchema = z.object({
  ok: z.literal(true),
  tool: z.string(),
  duration_ms: z.number().int().min(0),
  output: z.unknown(),
});
export type ToolExecutionResult = z.infer<typeof ToolExecutionResultSchema>;
