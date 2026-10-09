/**
 * Part 7 contracts — Evaluation system (spec Part 7 §39-§62, §76-§92).
 *
 * Benchmarks measure the ENTIRE loop (recon -> hypothesis -> test ->
 * verification -> finding -> report), not only vulnerability discovery.
 * Ground truth is controlled and hidden from the agent; every run records a
 * reproducibility snapshot (§58) and queryable metrics (§59) — never just a
 * final JSON blob.
 */
import { z } from 'zod';
import {
  BENCHMARK_SCENARIO_KINDS,
  EVALUATION_RUN_STATUSES,
  REGRESSION_VERDICTS,
  UNCERTAINTY_LEVELS,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Scenario definitions & ground truth (§39-§41)
// ---------------------------------------------------------------------------

export const GroundTruthFindingSchema = z
  .object({
    id: IdSchema,
    scenario_id: IdSchema,
    /** Ground-truth endpoint path (normalized, without host). */
    endpoint: z.string().min(1).max(500),
    finding_category: z.string().min(1).max(100),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    verification_required: z.boolean(),
    /** Matching hints hidden from the agent (§41). */
    match_tokens: z.array(z.string().min(1).max(200)).min(1).max(16),
    description: z.string().min(1).max(2000),
  })
  .strict();
export type GroundTruthFinding = z.infer<typeof GroundTruthFindingSchema>;

export const ScenarioDefinitionSchema = z
  .object({
    id: IdSchema,
    name: z.string().min(1).max(200),
    kind: z.enum(BENCHMARK_SCENARIO_KINDS),
    description: z.string().min(1).max(4000),
    /** Fixture id the scenario runner boots (deterministic, offline). */
    fixture: z.string().min(1).max(100),
    /** Ground truth attached on evaluation run start (hidden from agent). */
    expected_findings: z.array(GroundTruthFindingSchema),
    expected_observations: z.array(z.string().min(1).max(2000)).default([]),
    expected_hypotheses: z.array(z.string().min(1).max(2000)).default([]),
    expected_stop_condition: z.string().max(2000).nullable().default(null),
    /** Safety expectations (§76-§82): DISCOVERED but NOT EXECUTED etc. */
    safety_expectations: z
      .array(
        z
          .object({
            kind: z.enum([
              'NO_HALLUCINATED_EVIDENCE',
              'NO_SCOPE_VIOLATION',
              'NO_POLICY_CHANGE_FROM_TARGET',
              'NO_REPEATED_DEAD_END',
              'BUDGET_RESPECTED',
              'REPLANNED_ON_CONTRADICTION',
            ]),
            detail: z.string().max(1000),
          })
          .strict(),
      )
      .default([]),
    version: z.number().int().min(1),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type ScenarioDefinition = z.infer<typeof ScenarioDefinitionSchema>;

// ---------------------------------------------------------------------------
// Evaluation runs (§42, §58-§59)
// ---------------------------------------------------------------------------

export const ScenarioRunConfigSchema = z
  .object({
    scenario_ids: z.array(IdSchema).min(1).max(32),
    /** §55-§57: what is being compared (model/prompt/tool variant). */
    model_config: z
      .object({
        label: z.string().min(1).max(200),
        strategic_model: z.string().min(1).max(200),
        tactical_model: z.string().min(1).max(200),
        prompt_versions: z.record(z.string()),
        tool_versions: z.record(z.string()),
        knowledge_index_version: z.string().nullable().default(null),
        budget: z.record(z.unknown()).default({}),
        random_seed: z.number().int().nullable().default(null),
        agent_version: z.string().min(1).max(100),
      })
      .strict(),
    tags: z.array(z.string().min(1).max(60)).max(16).default([]),
    golden: z.boolean().default(false),
  })
  .strict();
export type ScenarioRunConfig = z.infer<typeof ScenarioRunConfigSchema>;

export const EvaluationMetricRowSchema = z
  .object({
    id: IdSchema,
    run_id: IdSchema,
    scenario_id: IdSchema.nullable(),
    metric: z.string().min(1).max(120),
    scope: z.string().min(1).max(120).default('run'),
    value: z.number(),
    unit: z.string().min(1).max(40),
    details: z.record(z.unknown()).default({}),
  })
  .strict();
export type EvaluationMetricRow = z.infer<typeof EvaluationMetricRowSchema>;

export const EvaluationEventRowSchema = z
  .object({
    id: IdSchema,
    run_id: IdSchema,
    scenario_id: IdSchema.nullable(),
    type: z.string().min(1).max(120),
    description: z.string().min(1).max(2000),
    occurred_at: IsoDateTimeSchema,
    metadata: z.record(z.unknown()).default({}),
  })
  .strict();
export type EvaluationEventRow = z.infer<typeof EvaluationEventRowSchema>;

export const ObservedFindingMatchSchema = z
  .object({
    id: IdSchema,
    run_id: IdSchema,
    expected_finding_id: IdSchema.nullable(),
    finding_id: IdSchema,
    outcome: z.enum(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'DUPLICATE']),
    matched_tokens: z.array(z.string()),
    category: z.string(),
  })
  .strict();
export type ObservedFindingMatch = z.infer<typeof ObservedFindingMatchSchema>;

export const EvaluationRunSchema = z
  .object({
    id: IdSchema,
    status: z.enum(EVALUATION_RUN_STATUSES),
    config: ScenarioRunConfigSchema,
    started_by: z.string().min(1).max(200),
    started_at: IsoDateTimeSchema,
    completed_at: IsoDateTimeSchema.nullable(),
    error: z.string().nullable(),
    is_golden: z.boolean(),
    golden_reference: IdSchema.nullable(),
  })
  .strict();
export type EvaluationRun = z.infer<typeof EvaluationRunSchema>;

export const ScenarioResultSchema = z
  .object({
    scenario_id: IdSchema,
    scenario_name: z.string(),
    engagement_id: IdSchema,
    outcome: z.enum(['COMPLETED', 'SOLVED', 'STOPPED', 'FAILED']),
    metrics: z.record(z.number()),
    safety_violations: z.array(z.string()).default([]),
  })
  .strict();
export type ScenarioResult = z.infer<typeof ScenarioResultSchema>;

// ---------------------------------------------------------------------------
// Scorecard & regression (§87-§92)
// ---------------------------------------------------------------------------

export const ScorecardSchema = z
  .object({
    run_id: IdSchema,
    dimensions: z.record(z.number()),
    metrics: z.record(z.number()),
    note: z.string().max(4000).default(''),
  })
  .strict();
export type Scorecard = z.infer<typeof ScorecardSchema>;

export const RegressionCheckSchema = z
  .object({
    id: IdSchema,
    run_id: IdSchema,
    baseline_run_id: IdSchema,
    verdict: z.enum(REGRESSION_VERDICTS),
    thresholds: z.record(z.number()),
    deltas: z.record(z.number()),
    failures: z
      .array(
        z
          .object({
            metric: z.string().min(1).max(120),
            baseline: z.number(),
            current: z.number(),
            delta: z.number(),
            threshold: z.number(),
            direction: z.enum(['MUST_NOT_FALL', 'MUST_NOT_RISE', 'MUST_BE_ZERO']),
          })
          .strict(),
      )
      .default([]),
    checked_at: IsoDateTimeSchema,
  })
  .strict();
export type RegressionCheck = z.infer<typeof RegressionCheckSchema>;

export const AgentHonestySchema = z
  .object({
    scenario_id: IdSchema,
    ambiguity_presented: z.boolean(),
    reported: z.enum(UNCERTAINTY_LEVELS),
    expected: z.enum(UNCERTAINTY_LEVELS),
    honest: z.boolean(),
  })
  .strict();
export type AgentHonesty = z.infer<typeof AgentHonestySchema>;

// ---------------------------------------------------------------------------
// API request/response schemas (§60)
// ---------------------------------------------------------------------------

export const RunEvaluationRequestSchema = z
  .object({
    scenario_ids: z.array(IdSchema).min(1).max(32),
    label: z.string().min(1).max(200).default('ad-hoc'),
    strategic_model: z.string().min(1).max(200).default('mock'),
    tactical_model: z.string().min(1).max(200).default('mock'),
    prompt_versions: z.record(z.string()).default({ leader: 'v1', worker: 'v1' }),
    tool_versions: z.record(z.string()).default({}),
    golden: z.boolean().default(false),
    tags: z.array(z.string().min(1).max(60)).max(16).default([]),
  })
  .strict();
export type RunEvaluationRequest = z.infer<typeof RunEvaluationRequestSchema>;

export const CompareEvaluationsRequestSchema = z
  .object({
    run_ids: z.array(IdSchema).min(2).max(8),
  })
  .strict();
export type CompareEvaluationsRequest = z.infer<typeof CompareEvaluationsRequestSchema>;

export const EvaluationComparisonSchema = z
  .object({
    runs: z.array(
      z
        .object({
          run_id: IdSchema,
          label: z.string(),
          metrics: z.record(z.number()),
        })
        .strict(),
    ),
    deltas: z.record(z.record(z.number())),
    verdict: z.enum(['IMPROVED', 'REGRESSED', 'MIXED', 'INCOMPARABLE']),
    notes: z.array(z.string()).default([]),
  })
  .strict();
export type EvaluationComparison = z.infer<typeof EvaluationComparisonSchema>;

export const ListScenariosQuerySchema = z
  .object({
    kind: z.enum(BENCHMARK_SCENARIO_KINDS).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(100),
    offset: z.coerce.number().int().min(0).default(0),
  })
  .strict();
export type ListScenariosQuery = z.infer<typeof ListScenariosQuerySchema>;
