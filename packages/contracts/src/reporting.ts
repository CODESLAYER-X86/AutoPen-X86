/**
 * Part 7 contracts — Verification, Reporting & Evaluation (spec Part 7 §4-§38,
 * §63-§68, §70-§75).
 *
 * The pipeline OBSERVATION -> HYPOTHESIS -> TEST -> EVIDENCE -> VERIFICATION ->
 * CONFIDENCE -> FINDING -> REPORT is fully structured: every verification
 * decision, confidence dimension, severity input, report claim and human
 * review is a validated record. The LLM may only ever SUPPLY inputs (e.g.
 * severity dimensions or summary wording); deterministic engines produce the
 * verdicts, scores and final artifacts.
 */
import { z } from 'zod';
import {
  EVIDENCE_QUALITY_LEVELS,
  HUMAN_REVIEW_DECISIONS,
  REPORT_FORMATS,
  REPORT_STATUSES,
  REPORT_TYPES,
  RETEST_OUTCOMES,
  RETEST_STATUSES,
  VERIFICATION_PLAN_STATUSES,
  VERIFICATION_STRATEGIES,
  VERIFICATION_VERDICTS,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Verification planning (§7-§14)
// ---------------------------------------------------------------------------

export const VerificationStrategySchema = z.enum(VERIFICATION_STRATEGIES);
export type VerificationStrategy = z.infer<typeof VerificationStrategySchema>;

export const EvidenceRequirementSchema = z
  .object({
    kind: z.enum([
      'REQUEST',
      'RESPONSE',
      'OBJECT_IDENTITY',
      'AUTHORIZATION_CONTEXT',
      'IDENTITY_ID',
      'CONTROL_RESPONSE',
      'BASELINE_RESPONSE',
      'STATE_BEFORE',
      'STATE_AFTER',
      'SOURCE_REFERENCE',
      'REPRODUCTION_RESULT',
    ]),
    description: z.string().min(1).max(500),
    required: z.boolean(),
  })
  .strict();
export type EvidenceRequirement = z.infer<typeof EvidenceRequirementSchema>;

/** §7: the evidence-sufficiency check that gates verification start. */
export const EvidenceSufficiencySchema = z
  .object({
    sufficient: z.boolean(),
    missing: z.array(z.string().min(1).max(200)),
    dimensions: z.record(z.boolean()),
    note: z.string().min(1).max(2000),
  })
  .strict();
export type EvidenceSufficiency = z.infer<typeof EvidenceSufficiencySchema>;

export const VerificationPlanSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    finding_id: IdSchema,
    /** §9: chosen strategy (or an ordered mix). */
    strategies: z.array(VerificationStrategySchema).min(1).max(6),
    /** §9: control conditions to run (e.g. OWN_OBJECT / FOREIGN_OBJECT). */
    controls: z.array(z.string().min(1).max(200)).max(8),
    expected_result: z.record(z.unknown()),
    required_evidence: z.array(EvidenceRequirementSchema).max(16),
    /** §7: recorded before verification is allowed to start. */
    sufficiency: EvidenceSufficiencySchema,
    status: z.enum(VERIFICATION_PLAN_STATUSES),
    result_id: IdSchema.nullable(),
    error: z.string().nullable(),
    created_at: IsoDateTimeSchema,
    completed_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type VerificationPlan = z.infer<typeof VerificationPlanSchema>;

export const AlternativeExplanationSchema = z
  .object({
    id: IdSchema,
    label: z.string().min(1).max(300),
    description: z.string().min(1).max(2000),
    refuted: z.boolean(),
    refutation: z.string().min(1).max(2000).nullable(),
    evidence_ids: z.array(IdSchema),
  })
  .strict();
export type AlternativeExplanation = z.infer<typeof AlternativeExplanationSchema>;

export const VerificationResultSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    finding_id: IdSchema,
    plan_id: IdSchema,
    status: z.enum(VERIFICATION_VERDICTS),
    confidence: z.number().min(0).max(1),
    supporting_evidence_ids: z.array(IdSchema),
    contradictory_evidence_ids: z.array(IdSchema),
    reproduced: z.boolean(),
    alternative_explanations: z.array(AlternativeExplanationSchema),
    reasoning_summary: z.string().min(1).max(8000),
    completed_at: IsoDateTimeSchema,
  })
  .strict();
export type VerificationResult = z.infer<typeof VerificationResultSchema>;

// ---------------------------------------------------------------------------
// Confidence (§15-§16) — deterministic, dimensioned, NOT severity
// ---------------------------------------------------------------------------

export const ConfidenceAssessmentSchema = z
  .object({
    confidence: z.number().min(0).max(1),
    level: z.enum(['HIGH', 'MEDIUM', 'LOW']),
    dimensions: z.record(z.number().min(0).max(1)),
    reasons: z.array(z.string().min(1).max(400)).max(12),
  })
  .strict();
export type ConfidenceAssessment = z.infer<typeof ConfidenceAssessmentSchema>;

// ---------------------------------------------------------------------------
// Severity & CVSS (§17-§18) — deterministic calculator, model supplies INPUTS
// ---------------------------------------------------------------------------

export const CVSS_VECTOR_METRICS = [
  'AV',
  'AC',
  'PR',
  'UI',
  'S',
  'C',
  'I',
  'A',
  'E',
  'RL',
  'RC',
  'CR',
  'IR',
  'AR',
] as const;
export type CvssMetric = (typeof CVSS_VECTOR_METRICS)[number];

export const SeverityInputSchema = z
  .object({
    /** Exploitability dimensions (CVSS 3.1). */
    attack_vector: z.enum(['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL']),
    attack_complexity: z.enum(['LOW', 'HIGH']),
    privileges_required: z.enum(['NONE', 'LOW', 'HIGH']),
    user_interaction: z.enum(['NONE', 'REQUIRED']),
    scope: z.enum(['UNCHANGED', 'CHANGED']),
    confidentiality_impact: z.enum(['NONE', 'LOW', 'HIGH']),
    integrity_impact: z.enum(['NONE', 'LOW', 'HIGH']),
    availability_impact: z.enum(['NONE', 'LOW', 'HIGH']),
    /** Business context (NOT part of the CVSS base score, §18). */
    data_sensitivity: z.enum(['LOW', 'MEDIUM', 'HIGH']).default('MEDIUM'),
    business_impact: z.enum(['LOW', 'MEDIUM', 'HIGH']).default('MEDIUM'),
    exploitability_ease: z.enum(['LOW', 'MEDIUM', 'HIGH']).default('MEDIUM'),
    /** Human/justification note (audited, never scored). */
    justification: z.string().max(2000).optional(),
  })
  .strict();
export type SeverityInput = z.infer<typeof SeverityInputSchema>;

export const SeverityAssessmentSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    finding_id: IdSchema,
    input: SeverityInputSchema,
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    /** Deterministic mapping; NEVER the model's opinion (§17). */
    source: z.enum(['CVSS_CALCULATOR', 'HUMAN_OVERRIDE']),
    cvss: z
      .object({
        version: z.literal('3.1'),
        vector: z.string().min(20).max(400),
        base_score: z.number().min(0).max(10),
        temporal_score: z.number().min(0).max(10).nullable(),
        environmental_score: z.number().min(0).max(10).nullable(),
        base_severity: z.enum(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
      })
      .strict(),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type SeverityAssessment = z.infer<typeof SeverityAssessmentSchema>;

// ---------------------------------------------------------------------------
// Finding lifecycle extension (§4-§6, §19-§20, §38, §70)
// ---------------------------------------------------------------------------

export const FindingLifecycleEventSchema = z
  .object({
    id: IdSchema,
    finding_id: IdSchema,
    from_status: z.string().min(1).max(40),
    to_status: z.string().min(1).max(40),
    reason: z.string().min(1).max(2000),
    actor: z.enum(['ENGINE', 'HUMAN']),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type FindingLifecycleEvent = z.infer<typeof FindingLifecycleEventSchema>;

export const FindingEvidenceQualitySchema = z
  .object({
    evidence_id: IdSchema,
    quality: z.enum(EVIDENCE_QUALITY_LEVELS),
    note: z.string().max(1000).optional(),
  })
  .strict();
export type FindingEvidenceQuality = z.infer<typeof FindingEvidenceQualitySchema>;

export const RetestRecordSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    finding_id: IdSchema,
    status: z.enum(RETEST_STATUSES),
    outcome: z.enum(RETEST_OUTCOMES).nullable(),
    verification_id: IdSchema.nullable(),
    note: z.string().max(4000).nullable(),
    requested_by: z.string().min(1).max(200),
    requested_at: IsoDateTimeSchema,
    completed_at: IsoDateTimeSchema.nullable(),
  })
  .strict();
export type RetestRecord = z.infer<typeof RetestRecordSchema>;

export const HumanReviewSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    finding_id: IdSchema,
    /** §67: the agent's original conclusion is preserved verbatim. */
    agent_status: z.string().min(1).max(40),
    agent_confidence: z.number().min(0).max(1).nullable(),
    decision: z.enum(HUMAN_REVIEW_DECISIONS),
    reviewer: z.string().min(1).max(200),
    reason: z.string().max(4000),
    /** §68: machine-usable feedback signal. */
    agent_human_disagreement: z.boolean(),
    resulting_status: z.string().min(1).max(40),
    metadata: z.record(z.unknown()),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type HumanReview = z.infer<typeof HumanReviewSchema>;

// ---------------------------------------------------------------------------
// Reports (§25-§34, §63-§66, §73)
// ---------------------------------------------------------------------------

export const ReportClaimSchema = z
  .object({
    id: IdSchema,
    finding_id: IdSchema,
    text: z.string().min(1).max(4000),
    evidence_ids: z.array(IdSchema),
    confidence: z.number().min(0).max(1),
    /** §33: claims whose scope exceeds their evidence are flagged/rewritten. */
    support: z.enum(['SUPPORTED', 'BROADER_THAN_EVIDENCE', 'UNSUPPORTED']),
    revision_of: IdSchema.nullable(),
  })
  .strict();
export type ReportClaim = z.infer<typeof ReportClaimSchema>;

export const ReportManifestSchema = z
  .object({
    report_hash: z.string().length(64),
    evidence_hashes: z.record(z.string().length(64)),
    finding_ids: z.array(IdSchema),
    generation_config: z.record(z.unknown()),
  })
  .strict();
export type ReportManifest = z.infer<typeof ReportManifestSchema>;

export const ReportValidationIssueSchema = z
  .object({
    code: z.string().min(1).max(80),
    message: z.string().min(1).max(2000),
    severity: z.enum(['ERROR', 'WARNING']),
    finding_id: IdSchema.nullable(),
    claim_id: IdSchema.nullable(),
  })
  .strict();
export type ReportValidationIssue = z.infer<typeof ReportValidationIssueSchema>;

export const ReportSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    type: z.enum(REPORT_TYPES),
    status: z.enum(REPORT_STATUSES),
    version: z.number().int().min(1),
    manifest: ReportManifestSchema.nullable(),
    claims: z.array(ReportClaimSchema),
    validation_issues: z.array(ReportValidationIssueSchema),
    /** Structured content used by every exporter (§63). */
    content: z.record(z.unknown()),
    redactions: z.array(
      z
        .object({
          location: z.string().min(1).max(200),
          rule: z.string().min(1).max(100),
        })
        .strict(),
    ),
    generated_at: IsoDateTimeSchema,
    generated_by: z.string().min(1).max(200),
  })
  .strict();
export type Report = z.infer<typeof ReportSchema>;

export const ReportExportSchema = z
  .object({
    report_id: IdSchema,
    format: z.enum(REPORT_FORMATS),
    byte_size: z.number().int().min(0),
    sha256: z.string().length(64),
    /** Where the rendered artifact lives (opaque storage pointer). */
    content_reference: z.string().min(1),
    created_at: IsoDateTimeSchema,
  })
  .strict();
export type ReportExport = z.infer<typeof ReportExportSchema>;

/** §75: reported terminal status is binary; uncertainty stays internal. */
export const ReportedFindingStatusSchema = z.enum(['VERIFIED', 'NOT_VERIFIED']);
export type ReportedFindingStatus = z.infer<typeof ReportedFindingStatusSchema>;

// ---------------------------------------------------------------------------
// API request/response schemas (§60, §67, reporting routes)
// ---------------------------------------------------------------------------

export const CreateCandidateFindingRequestSchema = z
  .object({
    hypothesis_id: IdSchema.nullable(),
    category: z.string().min(1).max(100),
    title: z.string().min(8).max(300),
    observed_behavior: z.string().min(8).max(4000),
    expected_behavior: z.string().max(4000).optional(),
    target_refs: z.array(IdSchema).max(16).default([]),
    endpoint_refs: z.array(z.string().min(1).max(500)).max(64).default([]),
    identity_refs: z.array(IdSchema).max(16).default([]),
    evidence_ids: z.array(IdSchema).max(128).default([]),
    test_ids: z.array(IdSchema).max(128).default([]),
  })
  .strict();
export type CreateCandidateFindingRequest = z.infer<typeof CreateCandidateFindingRequestSchema>;

export const VerifyFindingRequestSchema = z
  .object({
    strategies: z.array(VerificationStrategySchema).max(6).optional(),
  })
  .strict();
export type VerifyFindingRequest = z.infer<typeof VerifyFindingRequestSchema>;

export const ComputeSeverityRequestSchema = z.object({ input: SeverityInputSchema }).strict();
export type ComputeSeverityRequest = z.infer<typeof ComputeSeverityRequestSchema>;

export const ReviewFindingRequestSchema = z
  .object({
    decision: z.enum(HUMAN_REVIEW_DECISIONS),
    reason: z.string().min(1).max(4000),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    remediation: z.string().min(8).max(4000).optional(),
    duplicate_of: IdSchema.optional(),
  })
  .strict();
export type ReviewFindingRequest = z.infer<typeof ReviewFindingRequestSchema>;

export const RequestRetestRequestSchema = z
  .object({
    note: z.string().max(4000).optional(),
  })
  .strict();
export type RequestRetestRequest = z.infer<typeof RequestRetestRequestSchema>;

export const GenerateReportRequestSchema = z
  .object({
    type: z.enum(REPORT_TYPES).default('TECHNICAL'),
    formats: z.array(z.enum(REPORT_FORMATS)).min(1).max(4).default(['JSON', 'MARKDOWN']),
    title: z.string().min(1).max(300).optional(),
    include_evidence: z.boolean().default(true),
    include_remediation: z.boolean().default(true),
  })
  .strict();
export type GenerateReportRequest = z.infer<typeof GenerateReportRequestSchema>;

export const FindingEvidenceGraphSchema = z
  .object({
    finding: z.record(z.unknown()),
    verification: z.record(z.unknown()).nullable(),
    tests: z.array(z.record(z.unknown())),
    observations: z.array(z.record(z.unknown())),
    evidence: z.array(z.record(z.unknown())),
    requests: z.array(z.record(z.unknown())),
  })
  .strict();
export type FindingEvidenceGraph = z.infer<typeof FindingEvidenceGraphSchema>;

export const ExportReportRequestSchema = z
  .object({
    format: z.enum(REPORT_FORMATS).default('MARKDOWN'),
  })
  .strict();
export type ExportReportRequest = z.infer<typeof ExportReportRequestSchema>;

// ---------------------------------------------------------------------------
// Extended finding response (Part 7 §4-§20 fields surfaced to the UI)
// ---------------------------------------------------------------------------

export const FindingDetailResponseSchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    hypothesis_id: z.string().nullable(),
    title: z.string(),
    description: z.string(),
    severity: z.string(),
    status: z.string(),
    evidence_ids: z.array(z.string()),
    created_at: IsoDateTimeSchema,
    updated_at: IsoDateTimeSchema,
    category: z.string().nullable().optional(),
    confidence: z.number().nullable().optional(),
    confidence_level: z.string().nullable().optional(),
    confidence_reasons: z.array(z.string()).optional(),
    impact: z.string().nullable().optional(),
    remediation: z.string().nullable().optional(),
    verification_ids: z.array(z.string()).optional(),
    target_refs: z.array(z.string()).optional(),
    affected_endpoints: z.array(z.string()).optional(),
    affected_identities: z.array(z.string()).optional(),
    mode: z.string().optional(),
    retest_state: z.string().optional(),
    severity_source: z.string().optional(),
    cvss: z
      .object({
        version: z.string(),
        vector: z.string(),
        base_score: z.number(),
        temporal_score: z.number().nullable(),
        environmental_score: z.number().nullable(),
        base_severity: z.string(),
      })
      .nullable()
      .optional(),
    dedup_key: z.string().nullable().optional(),
    duplicate_of: z.string().nullable().optional(),
    observed_behavior: z.string().nullable().optional(),
    expected_behavior: z.string().nullable().optional(),
  })
  .strict();
export type FindingDetailResponse = z.infer<typeof FindingDetailResponseSchema>;

export const ReportSummarySchema = z
  .object({
    id: IdSchema,
    engagement_id: IdSchema,
    type: z.string(),
    status: z.string(),
    version: z.number(),
    title: z.string(),
    claims: z.array(z.unknown()),
    validation_issues: z.array(z.unknown()),
    redactions: z.array(z.unknown()),
    generated_by: z.string(),
    generated_at: IsoDateTimeSchema,
    manifest: z.record(z.unknown()).nullable(),
    content: z.record(z.unknown()),
  })
  .strict();
export type ReportSummary = z.infer<typeof ReportSummarySchema>;
