/**
 * Agent decision + worker contracts (Part 2 of the implementation spec).
 *
 * PRINCIPLE (inherited from Part 1, expanded): every machine-actionable model
 * output is a structured object validated against a zod schema. Free-form
 * prose NEVER drives actions. Malformed output (hallucinated enums, missing
 * fields, injected extra fields such as `shell_command`) fails closed.
 *
 * Two structured-output surfaces exist in Part 2:
 *   1. LeaderDecision — the strategic model's choice (spec §9)
 *   2. WorkerTurn — the tactical worker's per-step output, which is either a
 *      tool call request or a final structured result (spec §16/§17)
 *
 * Both are discriminated unions on a literal tag, `.strict()` everywhere, so
 * unknown fields and unknown enum values are rejected deterministically.
 */
import { z } from 'zod';
import { ValidationError } from '@aegis/shared';
import {
  DECISION_TYPES,
  HYPOTHESIS_TYPES,
  TASK_TYPES,
  WORKER_RESULT_STATUSES,
  WORKER_TYPES,
  ID_PATTERN,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

const ToolNameSchema = z
  .string()
  .min(3)
  .max(100)
  .regex(/^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/, 'Expected a dotted lowercase tool name');

const ConfidenceSchema = z.number().min(0).max(1);
const ReasoningSchema = z
  .string()
  .min(1)
  .max(2000)
  .describe('Concise decision rationale for audit; never private chain-of-thought');

const TaskConstraintsSchema = z
  .object({
    max_tool_calls: z.number().int().min(1).max(200).optional(),
    max_network_requests: z.number().int().min(0).max(500).optional(),
    max_duration_seconds: z.number().int().min(1).max(3600).optional(),
    max_response_bytes: z.number().int().min(256).max(104857600).optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Leader decision union (spec §9)
// ---------------------------------------------------------------------------

/** Task specification as proposed by the strategic leader (spec §9 example). */
export const LeaderTaskSpecSchema = z
  .object({
    objective: z.string().min(8).max(2000),
    task_type: z.enum(TASK_TYPES),
    worker_type: z.enum(WORKER_TYPES).optional(),
    hypothesis_id: IdSchema.optional(),
    depends_on: z.array(IdSchema).max(10).default([]),
    priority: ConfidenceSchema.optional(),
    /** Leader's estimate of how much this test distinguishes hypotheses (§21). */
    expected_information_gain: ConfidenceSchema.optional(),
    /** Leader's estimate of potential security impact (§20). */
    potential_impact: ConfidenceSchema.optional(),
    inputs: z.record(z.unknown()).optional(),
    allowed_tools: z.array(ToolNameSchema).max(20).optional(),
    identity_id: IdSchema.optional(),
    constraints: TaskConstraintsSchema.optional(),
    /** Endpoint/asset hint copied from the strategic context (free-form ref). */
    target_hint: z.string().max(500).optional(),
  })
  .strict();
export type LeaderTaskSpec = z.infer<typeof LeaderTaskSpecSchema>;

/** Hypothesis proposals/updates the leader may issue (spec §4 Replan, §22). */
export const LEADER_HYPOTHESIS_CHANGES = [
  'CREATE',
  'INCREASE_CONFIDENCE',
  'DECREASE_CONFIDENCE',
  'ACTIVATE',
  'ABANDON',
] as const;
export type LeaderHypothesisChange = (typeof LEADER_HYPOTHESIS_CHANGES)[number];

export const LeaderHypothesisSpecSchema = z
  .object({
    type: z.enum(HYPOTHESIS_TYPES),
    statement: z.string().min(8).max(2000),
    confidence: ConfidenceSchema.optional(),
    priority: ConfidenceSchema.optional(),
    parent_hypothesis_id: IdSchema.optional(),
    reasoning_summary: ReasoningSchema.optional(),
  })
  .strict();
export type LeaderHypothesisSpec = z.infer<typeof LeaderHypothesisSpecSchema>;

export const LeaderDecisionSchema = z.discriminatedUnion('decision', [
  z
    .object({
      decision: z.literal('CREATE_TASK'),
      reasoning_summary: ReasoningSchema,
      task: LeaderTaskSpecSchema,
    })
    .strict(),
  z
    .object({
      decision: z.literal('CREATE_PARALLEL_TASKS'),
      reasoning_summary: ReasoningSchema,
      tasks: z.array(LeaderTaskSpecSchema).min(2).max(8),
    })
    .strict(),
  z
    .object({
      decision: z.literal('UPDATE_HYPOTHESIS'),
      reasoning_summary: ReasoningSchema,
      hypothesis_id: IdSchema.optional(),
      change: z.enum(LEADER_HYPOTHESIS_CHANGES),
      confidence: ConfidenceSchema.optional(),
      hypothesis: LeaderHypothesisSpecSchema.optional(),
    })
    .strict(),
  z
    .object({
      decision: z.literal('REQUEST_KNOWLEDGE'),
      reasoning_summary: ReasoningSchema,
      query: z.string().min(4).max(1000),
    })
    .strict(),
  z
    .object({
      decision: z.literal('REQUEST_RECON'),
      reasoning_summary: ReasoningSchema,
      focus: z.string().min(4).max(1000),
      task: LeaderTaskSpecSchema.partial({ task_type: true }).optional(),
    })
    .strict(),
  z
    .object({
      decision: z.literal('REQUEST_VERIFICATION'),
      reasoning_summary: ReasoningSchema,
      hypothesis_id: IdSchema,
      aspect: z.string().max(500).optional(),
    })
    .strict(),
  z
    .object({
      decision: z.literal('WAIT'),
      reasoning_summary: ReasoningSchema,
      duration_hint_seconds: z.number().int().min(1).max(3600).optional(),
    })
    .strict(),
  z
    .object({
      decision: z.literal('STOP'),
      reasoning_summary: ReasoningSchema,
      objective_satisfied: z.boolean(),
      summary: z.string().max(4000).optional(),
    })
    .strict(),
  z
    .object({
      decision: z.literal('PAUSE'),
      reasoning_summary: ReasoningSchema,
    })
    .strict(),
]);
export type LeaderDecision = z.infer<typeof LeaderDecisionSchema>;

/** All valid decision tags (useful for prompt construction + tests). */
export const LEADER_DECISION_TYPES = DECISION_TYPES;

/**
 * Validates a raw leader model output as a strategic decision.
 * Malformed output fails closed with a typed ValidationError.
 */
export function validateLeaderDecision(raw: unknown): LeaderDecision {
  const parsed = LeaderDecisionSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ValidationError(
      'Leader model output failed decision schema validation',
      'LEADER_DECISION_INVALID',
      parsed.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// Worker task packet (spec §13) — the compact, compiled worker input
// ---------------------------------------------------------------------------

export const WorkerTaskPacketSchema = z
  .object({
    task_id: IdSchema,
    engagement_id: IdSchema,
    run_id: IdSchema,
    type: z.enum(TASK_TYPES),
    objective: z.string().min(1).max(2000),
    hypothesis: z
      .object({ id: IdSchema, statement: z.string().max(2000), confidence: ConfidenceSchema })
      .nullable(),
    identity_id: IdSchema.nullable(),
    allowed_tools: z.array(ToolNameSchema).max(20),
    constraints: TaskConstraintsSchema,
    /** Trusted, application-derived compact facts (§15: structured over prose). */
    context: z.record(z.unknown()),
    /**
     * Target-derived content. ALWAYS rendered inside explicit untrusted
     * delimiters by the prompt builder (§60-§62); never merged into trusted
     * context.
     */
    untrusted_context: z.record(z.unknown()),
    expected_output: z.literal('structured_observation'),
    /** Idempotency key carried through compilation (§65). */
    idempotency_key: z.string().min(1).max(200),
  })
  .strict();
export type WorkerTaskPacket = z.infer<typeof WorkerTaskPacketSchema>;

// ---------------------------------------------------------------------------
// Worker output contract (spec §16, §17)
// ---------------------------------------------------------------------------

export const WORKER_HYPOTHESIS_CHANGES = [
  'CREATE',
  'INCREASE_CONFIDENCE',
  'DECREASE_CONFIDENCE',
  'SUPPORT',
  'CONTRADICT',
  'CONFIRM',
  'DISPROVE',
  'ABANDON',
] as const;
export type WorkerHypothesisChange = (typeof WORKER_HYPOTHESIS_CHANGES)[number];

export const WorkerObservationSchema = z
  .object({
    type: z.string().min(3).max(100),
    description: z.string().min(1).max(2000),
    confidence: ConfidenceSchema,
    evidence_refs: z.array(z.string().regex(ID_PATTERN)).max(20).optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();
export type WorkerObservation = z.infer<typeof WorkerObservationSchema>;

export const WorkerHypothesisUpdateSchema = z
  .object({
    hypothesis_id: IdSchema.optional(),
    change: z.enum(WORKER_HYPOTHESIS_CHANGES),
    confidence: ConfidenceSchema.optional(),
    statement: z.string().min(8).max(2000).optional(),
    type: z.enum(HYPOTHESIS_TYPES).optional(),
    reason: z.string().max(1000).optional(),
  })
  .strict();
export type WorkerHypothesisUpdate = z.infer<typeof WorkerHypothesisUpdateSchema>;

export const WorkerOutputSchema = z
  .object({
    task_id: IdSchema,
    status: z.enum(WORKER_RESULT_STATUSES),
    observations: z.array(WorkerObservationSchema).max(20).default([]),
    evidence_ids: z.array(IdSchema).max(50).default([]),
    hypothesis_updates: z.array(WorkerHypothesisUpdateSchema).max(20).default([]),
    /** Structured blockers for NEEDS_* statuses (spec §17). */
    needs: z
      .object({
        context: z.array(z.string().max(500)).max(10).optional(),
        tools: z.array(ToolNameSchema).max(10).optional(),
        identity: z.string().max(500).optional(),
      })
      .strict()
      .optional(),
    recommended_next_action: z
      .object({
        type: z.enum(['VERIFY', 'CREATE_TASK', 'WAIT', 'NONE']),
        reason: z.string().max(1000),
      })
      .strict()
      .optional(),
    error: z.string().max(2000).optional(),
  })
  .strict();
export type WorkerOutput = z.infer<typeof WorkerOutputSchema>;

/** Validates a worker model's final result. Fails closed. */
export function validateWorkerOutput(raw: unknown): WorkerOutput {
  const parsed = WorkerOutputSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ValidationError(
      'Worker model output failed schema validation',
      'WORKER_OUTPUT_INVALID',
      parsed.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return parsed.data;
}

/**
 * One worker reasoning step: request a deterministic tool call, or finalize.
 * The runtime (not the model) decides whether a requested call is allowed.
 */
export const WorkerTurnSchema = z.discriminatedUnion('type', [
  z
    .object({
      type: z.literal('TOOL_CALL'),
      tool: ToolNameSchema,
      input: z.record(z.unknown()),
      reason: z.string().max(1000).optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal('FINAL'),
      result: WorkerOutputSchema,
    })
    .strict(),
]);
export type WorkerTurn = z.infer<typeof WorkerTurnSchema>;

export function validateWorkerTurn(raw: unknown): WorkerTurn {
  const parsed = WorkerTurnSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ValidationError(
      'Worker turn failed schema validation',
      'WORKER_TURN_INVALID',
      parsed.error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
    );
  }
  return parsed.data;
}

// ---------------------------------------------------------------------------
// API-facing request schemas (Part 2)
// ---------------------------------------------------------------------------

export const StartAgentRunRequestSchema = z
  .object({
    reason: z.string().max(1000).optional(),
  })
  .strict();
export type StartAgentRunRequest = z.infer<typeof StartAgentRunRequestSchema>;

/** Human overrides (spec §46). All are audited; scope changes excluded here. */
export const HumanOverrideSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('ADD_CTF_CLUE'),
      clue: z.string().min(4).max(4000),
    })
    .strict(),
  z
    .object({
      kind: z.literal('PRIORITIZE_HYPOTHESIS'),
      hypothesis_id: IdSchema,
      priority: ConfidenceSchema,
      reason: z.string().max(1000).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('CANCEL_TASK'),
      task_id: IdSchema,
      reason: z.string().max(1000).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('REQUEST_VERIFICATION'),
      hypothesis_id: IdSchema,
      reason: z.string().max(1000).optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal('PAUSE_RUN'),
      reason: z.string().max(1000).optional(),
    })
    .strict(),
]);
export type HumanOverride = z.infer<typeof HumanOverrideSchema>;

// ---------------------------------------------------------------------------
// API-facing response schemas (mirror database records)
// ---------------------------------------------------------------------------

export const AgentRunResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    status: z.string(),
    reason: z.string().nullable(),
    strategy_version: z.number().int().nullable(),
    leader_model: z.string(),
    worker_model: z.string(),
    metrics: z.record(z.unknown()),
    started_at: IsoDateTimeSchema.nullable(),
    ended_at: IsoDateTimeSchema.nullable(),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
  })
  .strict();
export type AgentRunResponse = z.infer<typeof AgentRunResponseSchema>;

export const TaskResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    run_id: IdSchema.nullable(),
    hypothesis_id: IdSchema.nullable(),
    type: z.string(),
    objective: z.string(),
    worker_type: z.string(),
    status: z.string(),
    priority: z.number(),
    depends_on: z.array(z.string()),
    allowed_tools: z.array(z.string()),
    constraints: z.record(z.unknown()),
    attempts: z.number().int(),
    max_attempts: z.number().int(),
    failure_code: z.string().nullable(),
    failure_reason: z.string().nullable(),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
    started_at: IsoDateTimeSchema.nullable(),
    completed_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type TaskResponse = z.infer<typeof TaskResponseSchema>;

export const HypothesisResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    type: z.string(),
    statement: z.string(),
    status: z.string(),
    confidence: z.number(),
    priority: z.number(),
    source: z.string(),
    parent_hypothesis_id: IdSchema.nullable(),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
    confirmed_at: IsoDateTimeSchema.nullable(),
    disproved_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type HypothesisResponse = z.infer<typeof HypothesisResponseSchema>;

export const ObservationResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    task_id: IdSchema.nullable(),
    hypothesis_id: IdSchema.nullable(),
    type: z.string(),
    description: z.string(),
    confidence: z.number(),
    evidence_ids: z.array(z.string()),
    metadata: z.record(z.unknown()),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type ObservationResponse = z.infer<typeof ObservationResponseSchema>;

export const DeadEndResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    hypothesis_id: IdSchema.nullable(),
    description: z.string(),
    tests: z.array(z.string()),
    reason: z.string(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type DeadEndResponse = z.infer<typeof DeadEndResponseSchema>;

export const StrategyResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    run_id: IdSchema.nullable(),
    version: z.number().int(),
    summary: z.string(),
    focus: z.string(),
    reason: z.string(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type StrategyResponse = z.infer<typeof StrategyResponseSchema>;

export const FindingResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    hypothesis_id: IdSchema.nullable(),
    title: z.string(),
    description: z.string(),
    severity: z.string(),
    status: z.string(),
    evidence_ids: z.array(z.string()),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
  })
  .strict();
export type FindingResponse = z.infer<typeof FindingResponseSchema>;

export const AgentMetricsResponseSchema = z
  .object({
    engagement_id: IdSchema,
    runs: z.record(z.unknown()),
    cycles: z.record(z.unknown()),
    tasks: z.record(z.unknown()),
    hypotheses: z.record(z.unknown()),
    workers: z.record(z.unknown()),
    tokens: z.record(z.unknown()),
    tool_calls: z.record(z.unknown()),
    observations: z.number(),
    findings: z.number(),
    tests: z.number(),
    network_requests: z.number(),
  })
  .strict();
export type AgentMetricsResponse = z.infer<typeof AgentMetricsResponseSchema>;

// Backwards-compatible alias: Part 1 exposed a single v0 decision schema. The
// Part 2 union supersedes it; the old test vocabulary was replaced in lockstep.
export const AgentDecisionSchema = LeaderDecisionSchema;
export const validateAgentDecision = validateLeaderDecision;
