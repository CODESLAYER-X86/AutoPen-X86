/**
 * Agent decision contracts (spec §20 — established in Part 1, expanded in
 * Part 2). PRINCIPLE: every machine-actionable model output is a structured
 * object validated against a schema. Free-form prose never drives actions.
 */
import { z } from 'zod';
import { ValidationError } from '@aegis/shared';

export const AGENT_DECISIONS = [
  'CREATE_TASK',
  'INVESTIGATE',
  'VERIFY_FINDING',
  'REPLAN',
  'CONTINUE',
  'STOP',
] as const;

/** v0 strategic-decision schema — the Part 2 planner will extend this. */
export const AgentDecisionSchema = z
  .object({
    decision: z.enum(AGENT_DECISIONS),
    reason: z.string().min(1).max(4000),
    priority: z.number().min(0).max(1),
    task_type: z.string().max(100).optional(),
    target: z.string().max(200).optional(),
    identity: z.string().max(200).optional(),
  })
  .strict();
export type AgentDecision = z.infer<typeof AgentDecisionSchema>;

/**
 * Validates a raw model output blob as an agent decision. Malformed output
 * (hallucinated enum values, missing fields, extra fields) fails closed.
 */
export function validateAgentDecision(raw: unknown): AgentDecision {
  const parsed = AgentDecisionSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ValidationError(
      'Model output failed schema validation',
      'MODEL_OUTPUT_INVALID',
      parsed.error.issues.map((issue) => ({ path: issue.path.join('.'), message: issue.message })),
    );
  }
  return parsed.data;
}
