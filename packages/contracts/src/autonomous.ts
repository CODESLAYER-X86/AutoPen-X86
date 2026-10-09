/**
 * Part 6 contracts — Autonomous Pentest & CTF Engine (spec Part 6 §6, §9,
 * §12-§13, §17, §25-§28, §29-§31, §45-§46, §48-§51, §52-§53, §58-§60,
 * §65, §72, §79).
 *
 * The engine is domain-aware but execution-agnostic: these contracts define
 * the STRUCTURED decisions the engine records and the deterministic state it
 * persists. Model output never bypasses validation; untrusted target content
 * is carried separately from trusted engine state.
 */
import { z } from 'zod';
import {
  APPROVAL_DECISIONS,
  AUTONOMOUS_PHASES,
  AUTONOMOUS_TERMINAL_PHASES,
  BRANCH_STATUSES,
  CTF_CLUE_SOURCES,
  CTF_CLUE_STATUSES,
  CTF_STATUSES,
  ENGINE_RISK_LEVELS,
  FLAG_CONDITION_STATUSES,
  STOP_REASONS,
  REPLAN_TRIGGERS,
  TEST_RESULT_OUTCOMES,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Engine state (§6)
// ---------------------------------------------------------------------------

export const AutonomousEngineStateSchema = z
  .object({
    engagement_id: IdSchema,
    phase: z.enum(AUTONOMOUS_PHASES),
    is_terminal: z.boolean(),
    mode: z.enum(['RECON_MODE', 'PENTEST_MODE', 'CTF_MODE']),
    waiting_reason: z.string().nullable(),
    strategy_summary: z.string().nullable(),
    replan_count: z.number().int().min(0),
    cycle_count: z.number().int().min(0),
    last_replan_trigger: z.string().nullable(),
    stop_reason: z.enum(STOP_REASONS).nullable(),
    engine_instance_id: z.string().nullable(),
    started_at: IsoDateTimeSchema.nullable(),
    finished_at: IsoDateTimeSchema.nullable(),
    last_transition_at: IsoDateTimeSchema,
  })
  .strict();
export type AutonomousEngineState = z.infer<typeof AutonomousEngineStateSchema>;

/** Terminal phase view used by the status endpoint. */
export const TERMINAL_PHASES = AUTONOMOUS_TERMINAL_PHASES;

// ---------------------------------------------------------------------------
// Reconnaissance plan (§9-§11)
// ---------------------------------------------------------------------------

export const ReconPhaseSchema = z.enum([
  'SCOPE_VALIDATION',
  'TARGET_LOAD',
  'IDENTITY_LOAD',
  'SESSION_INIT',
  'PASSIVE_DISCOVERY',
  'ACTIVE_DISCOVERY',
  'APPLICATION_MAPPING',
]);
export type ReconPhase = z.infer<typeof ReconPhaseSchema>;

export const ReconPlanTaskSchema = z
  .object({
    /** Deterministic recon stage the task belongs to (§9). */
    stage: ReconPhaseSchema,
    objective: z.string().min(8).max(2000),
    task_type: z.string(),
    worker_type: z.enum(['HTTP_WORKER', 'BROWSER_WORKER', 'SOURCE_WORKER', 'ANALYSIS_WORKER']),
    identity_id: IdSchema.nullable(),
    target_hint: z.string().max(500).nullable(),
    /** §11: every active discovery task carries reason/scope/gain/cost/risk. */
    expected_information_gain: z.number().min(0).max(1),
    estimated_cost: z.number().min(0).max(1),
    risk: z.enum(ENGINE_RISK_LEVELS),
    reason: z.string().min(4).max(2000),
    paths: z.array(z.string().max(500)).max(32).default([]),
    fingerprint: z.string().min(8),
  })
  .strict();
export type ReconPlanTask = z.infer<typeof ReconPlanTaskSchema>;

export const ReconPlanSchema = z
  .object({
    engagement_id: IdSchema,
    level: z.number().int().min(0).max(4),
    tasks: z.array(ReconPlanTaskSchema).max(24),
    passive_sources: z.array(z.string()).default([]),
    bounded: z.boolean(),
  })
  .strict();
export type ReconPlan = z.infer<typeof ReconPlanSchema>;

// ---------------------------------------------------------------------------
// Attack-surface graph projection (§12-§13)
// ---------------------------------------------------------------------------

export const GraphNodeSchema = z
  .object({
    id: z.string().min(1),
    type: z.string().min(1),
    label: z.string().max(500),
    status: z.string().max(64).nullable().default(null),
    refs: z.array(z.string()).default([]),
  })
  .strict();
export type GraphNode = z.infer<typeof GraphNodeSchema>;

export const GraphEdgeSchema = z
  .object({
    source: z.string().min(1),
    target: z.string().min(1),
    relation: z.string().min(1),
  })
  .strict();
export type GraphEdge = z.infer<typeof GraphEdgeSchema>;

export const AttackSurfaceGraphSchema = z
  .object({
    engagement_id: IdSchema,
    nodes: z.array(GraphNodeSchema).max(2000),
    edges: z.array(GraphEdgeSchema).max(8000),
    counts: z.record(z.number().int().min(0)),
    truncated: z.boolean(),
  })
  .strict();
export type AttackSurfaceGraph = z.infer<typeof AttackSurfaceGraphSchema>;

// ---------------------------------------------------------------------------
// Reasoning branches (§65-§66)
// ---------------------------------------------------------------------------

export const ReasoningBranchSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    parent_branch_id: IdSchema.nullable(),
    origin: z.string().max(64),
    origin_ref: z.string().nullable(),
    focus: z.string().max(500),
    hypothesis_ids: z.array(IdSchema),
    score: z.number().min(0).max(1),
    status: z.enum(BRANCH_STATUSES),
    pruned_reason: z.string().nullable(),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
  })
  .strict();
export type ReasoningBranch = z.infer<typeof ReasoningBranchSchema>;

// ---------------------------------------------------------------------------
// CTF mode (§4, §29-§31)
// ---------------------------------------------------------------------------

export const CtfInterpretationSchema = z
  .object({
    concept: z.string().min(1).max(200),
    confidence: z.number().min(0).max(1),
    rationale: z.string().max(2000),
  })
  .strict();
export type CtfInterpretation = z.infer<typeof CtfInterpretationSchema>;

export const CtfContextSchema = z
  .object({
    engagement_id: IdSchema,
    title: z.string(),
    description: z.string(),
    hints: z.array(z.string()),
    flag_format: z.string().nullable(),
    status: z.enum(CTF_STATUSES),
    flag_value: z.string().nullable(),
    flag_evidence_id: IdSchema.nullable(),
    solved_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type CtfContext = z.infer<typeof CtfContextSchema>;

export const CtfClueSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    source: z.enum(CTF_CLUE_SOURCES),
    text: z.string(),
    interpretations: z.array(CtfInterpretationSchema),
    branch_id: IdSchema.nullable(),
    status: z.enum(CTF_CLUE_STATUSES),
    dead_end_reason: z.string().nullable(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type CtfClue = z.infer<typeof CtfClueSchema>;

export const FlagConditionSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    hypothesis_id: IdSchema.nullable(),
    condition_description: z.string(),
    pattern: z.string().nullable(),
    evidence_ids: z.array(IdSchema),
    evidence_kinds: z.array(z.string()),
    detected_value: z.string().nullable(),
    status: z.enum(FLAG_CONDITION_STATUSES),
    detected_at: IsoDateTimeSchema.nullable(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type FlagCondition = z.infer<typeof FlagConditionSchema>;

// ---------------------------------------------------------------------------
// Coverage model (§51)
// ---------------------------------------------------------------------------

export const CoverageReportSchema = z
  .object({
    engagement_id: IdSchema,
    endpoint_coverage: z.number().min(0).max(1),
    identity_coverage: z.number().min(0).max(1),
    workflow_coverage: z.number().min(0).max(1),
    parameter_coverage: z.number().min(0).max(1),
    object_coverage: z.number().min(0).max(1),
    hypothesis_coverage: z.record(z.number().min(0).max(1)),
    counts: z.record(z.number().int().min(0)),
    note: z.string(),
  })
  .strict();
export type CoverageReport = z.infer<typeof CoverageReportSchema>;

// ---------------------------------------------------------------------------
// Live agent timeline (§53)
// ---------------------------------------------------------------------------

export const TimelineEntrySchema = z
  .object({
    event_id: z.string(),
    occurred_at: IsoDateTimeSchema,
    type: z.string(),
    phase: z.string().nullable(),
    summary: z.string().max(1000),
    refs: z.record(z.string()),
  })
  .strict();
export type TimelineEntry = z.infer<typeof TimelineEntrySchema>;

export const TimelineSchema = z
  .object({
    engagement_id: IdSchema,
    entries: z.array(TimelineEntrySchema),
    total: z.number().int().min(0),
  })
  .strict();
export type Timeline = z.infer<typeof TimelineSchema>;

// ---------------------------------------------------------------------------
// Human approvals (§48-§49)
// ---------------------------------------------------------------------------

export const ApprovalRecordSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    task_id: IdSchema.nullable(),
    risk: z.enum(ENGINE_RISK_LEVELS),
    action_summary: z.string(),
    requested_by: z.string(),
    decision: z.enum(APPROVAL_DECISIONS).nullable(),
    decided_by: z.string().nullable(),
    decided_reason: z.string().nullable(),
    created_at: IsoDateTimeSchema,
    decided_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type ApprovalRecord = z.infer<typeof ApprovalRecordSchema>;

// ---------------------------------------------------------------------------
// Experimental test registry view (§60)
// ---------------------------------------------------------------------------

export const TestRegistryEntrySchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    task_id: IdSchema.nullable(),
    hypothesis_id: IdSchema.nullable(),
    test_type: z.string(),
    target: z.string(),
    identity: z.string().nullable(),
    mutation_summary: z.string().nullable(),
    fingerprint: z.string(),
    status: z.string(),
    result: z.enum(TEST_RESULT_OUTCOMES).nullable(),
    expected_signal: z.string().nullable(),
    actual_signal: z.string().nullable(),
    result_summary: z.string().nullable(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type TestRegistryEntry = z.infer<typeof TestRegistryEntrySchema>;

// ---------------------------------------------------------------------------
// Benchmark evaluation (§79, §84)
// ---------------------------------------------------------------------------

export const BenchmarkMetricsSchema = z
  .object({
    time_to_first_finding_ms: z.number().nullable(),
    time_to_verified_finding_ms: z.number().nullable(),
    time_to_solve_ms: z.number().nullable(),
    false_positive_rate: z.number().min(0).max(1).nullable(),
    duplicate_test_rate: z.number().min(0).max(1).nullable(),
    coverage: z.record(z.number()).nullable(),
    requests_per_finding: z.number().nullable(),
    model_tokens_per_finding: z.number().nullable(),
    knowledge_calls: z.number().int().min(0),
    verification_success_rate: z.number().min(0).max(1).nullable(),
    solved: z.boolean(),
    expected_findings_found: z.number().int().min(0),
    expected_findings_total: z.number().int().min(0),
    expected_dead_ends_avoided: z.number().int().min(0),
    total_tests: z.number().int().min(0),
    total_model_calls: z.number().int().min(0),
    total_http_requests: z.number().int().min(0),
  })
  .strict();
export type BenchmarkMetrics = z.infer<typeof BenchmarkMetricsSchema>;

export const BenchmarkDefinitionSchema = z
  .object({
    name: z.string(),
    description: z.string(),
    mode: z.enum(['PENTEST', 'CTF']),
    expected_findings: z.array(z.string()),
    expected_dead_ends: z.array(z.string()),
    measures: z.array(z.string()),
  })
  .strict();
export type BenchmarkDefinition = z.infer<typeof BenchmarkDefinitionSchema>;

export const BenchmarkRunSchema = z
  .object({
    id: IdSchema,
    benchmark: z.string(),
    engagement_id: IdSchema,
    outcome: z.enum(['COMPLETED', 'SOLVED', 'STOPPED', 'FAILED']),
    metrics: BenchmarkMetricsSchema,
    started_at: IsoDateTimeSchema,
    completed_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type BenchmarkRun = z.infer<typeof BenchmarkRunSchema>;

// ---------------------------------------------------------------------------
// API request/response schemas (§72)
// ---------------------------------------------------------------------------

export const StartAutonomousRequestSchema = z
  .object({
    reason: z.string().max(2000).optional(),
  })
  .strict();
export type StartAutonomousRequest = z.infer<typeof StartAutonomousRequestSchema>;

export const UpsertCtfContextRequestSchema = z
  .object({
    title: z.string().max(500).optional(),
    description: z.string().max(10_000).optional(),
    hints: z.array(z.string().max(2000)).max(16).optional(),
    flag_format: z.string().max(500).optional().nullable(),
  })
  .strict();
export type UpsertCtfContextRequest = z.infer<typeof UpsertCtfContextRequestSchema>;

export const AddCtfClueRequestSchema = z
  .object({
    text: z.string().min(4).max(2000),
    source: z.enum(CTF_CLUE_SOURCES).optional(),
  })
  .strict();
export type AddCtfClueRequest = z.infer<typeof AddCtfClueRequestSchema>;

export const PrioritizeRequestSchema = z
  .object({
    hypothesis_id: IdSchema,
    note: z.string().max(2000).optional(),
  })
  .strict();
export type PrioritizeRequest = z.infer<typeof PrioritizeRequestSchema>;

export const ApproveRequestSchema = z
  .object({
    approval_id: IdSchema.optional(),
    task_id: IdSchema.optional(),
    reason: z.string().max(2000).optional(),
  })
  .strict();
export type ApproveRequest = z.infer<typeof ApproveRequestSchema>;

export const RejectRequestSchema = z.object({ reason: z.string().max(2000).optional() }).strict();
export type RejectRequest = z.infer<typeof RejectRequestSchema>;

export const ReplanRequestSchema = z
  .object({
    trigger: z.enum(REPLAN_TRIGGERS).optional(),
    note: z.string().max(2000).optional(),
  })
  .strict();
export type ReplanRequest = z.infer<typeof ReplanRequestSchema>;

// Response envelopes ------------------------------------------------------------

export const AutonomousStatusResponseSchema = z
  .object({
    engine: AutonomousEngineStateSchema,
    task_summary: z.record(z.number().int().min(0)),
    hypothesis_summary: z.record(z.number().int().min(0)),
    finding_summary: z.record(z.number().int().min(0)),
    verification_summary: z.record(z.number().int().min(0)),
    budget: z
      .object({
        limits: z.record(z.number().nullable()),
        usage: z.record(z.number().int().min(0)),
      })
      .nullable(),
    current_run: z
      .object({
        run_id: IdSchema,
        status: z.string(),
        cycles: z.number().int().min(0),
      })
      .nullable(),
    ctf: z
      .object({
        status: z.enum(CTF_STATUSES),
        clues_total: z.number().int().min(0),
        flag_conditions_total: z.number().int().min(0),
      })
      .nullable(),
  })
  .strict();
export type AutonomousStatusResponse = z.infer<typeof AutonomousStatusResponseSchema>;

export const CoverageResponseSchema = z.object({ coverage: CoverageReportSchema }).strict();

export const GraphResponseSchema = z.object({ graph: AttackSurfaceGraphSchema }).strict();

export const TimelineResponseSchema = z.object({ timeline: TimelineSchema }).strict();

export const BranchListResponseSchema = z
  .object({ items: z.array(ReasoningBranchSchema), total: z.number().int().min(0) })
  .strict();

export const CtfResponseSchema = z
  .object({
    context: CtfContextSchema,
    clues: z.array(CtfClueSchema),
    flag_conditions: z.array(FlagConditionSchema),
  })
  .strict();

export const ApprovalListResponseSchema = z
  .object({ items: z.array(ApprovalRecordSchema), total: z.number().int().min(0) })
  .strict();

export const ApprovalDecisionResponseSchema = z
  .object({
    approval: ApprovalRecordSchema,
    task_status: z.string().nullable(),
  })
  .strict();

export const TestRegistryResponseSchema = z
  .object({ items: z.array(TestRegistryEntrySchema), total: z.number().int().min(0) })
  .strict();

export const ReconPlanResponseSchema = z.object({ plan: ReconPlanSchema }).strict();

export const BenchmarkListResponseSchema = z
  .object({ items: z.array(BenchmarkDefinitionSchema) })
  .strict();

export const BenchmarkRunsResponseSchema = z
  .object({ items: z.array(BenchmarkRunSchema) })
  .strict();

export const ReplanResponseSchema = z
  .object({
    replanned: z.boolean(),
    replan_count: z.number().int().min(0),
    phase: z.enum(AUTONOMOUS_PHASES),
  })
  .strict();
