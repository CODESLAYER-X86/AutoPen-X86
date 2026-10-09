/**
 * Security Reasoning Engine contracts (spec Part 4).
 *
 * Deterministic extraction shapes: endpoints, parameters, authorization
 * matrix, workflows, data flows, signals, objects, differential results,
 * verification records and the attack-surface graph.
 *
 * Central principle (spec §0): OBSERVATION != VULNERABILITY. Every shape
 * below represents evidence or candidates — never a confirmed finding.
 */
import { z } from 'zod';
import {
  ACCESS_OUTCOMES,
  ATTACK_EDGE_RELATIONS,
  ATTACK_NODE_TYPES,
  CONFIDENCE_CATEGORIES,
  CORRELATION_KINDS,
  DATA_FLOW_SINK_KINDS,
  DATA_FLOW_SOURCE_KINDS,
  DISCOVERY_SOURCES,
  ENDPOINT_STATUSES,
  EVIDENCE_STRENGTH_LEVELS,
  MUTATION_CATEGORIES,
  PARAMETER_LOCATIONS,
  PARAMETER_SEMANTICS,
  SIGNAL_STATUSES,
  SIGNAL_TYPES,
  TRANSITION_OBSERVATION_KINDS,
  VALUE_CHARACTERISTICS,
  VERIFICATION_CHECK_STATUSES,
  VERIFICATION_STATUSES,
  WORKFLOW_STATUSES,
} from '@aegis/shared';
import { HttpMutationSchema } from './http.js';

// ---------------------------------------------------------------------------
// Endpoints (spec §7-§13).
// ---------------------------------------------------------------------------

export const EndpointMethodObservationSchema = z.object({
  method: z.string(),
  observation_count: z.number().int().min(1),
  identity_ids: z.array(z.string()).max(64),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type EndpointMethodObservation = z.infer<typeof EndpointMethodObservationSchema>;

export const EndpointRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  /** Deterministic fingerprint over scheme|host|port|canonical path (§8). */
  fingerprint: z.string(),
  scheme: z.string(),
  host: z.string(),
  port: z.number().int(),
  /** First observed concrete path (never a fact about the schema). */
  path: z.string(),
  /** Canonicalization candidate, e.g. /api/user/{id} (§7). */
  canonical_path: z.string(),
  /** 0..1 confidence in the canonical candidate (§7). */
  canonical_confidence: z.number().min(0).max(1),
  /** Endpoint clustering family (§86), e.g. /api/users. */
  resource_family: z.string().nullable(),
  /** Detected API version prefix (§87), e.g. v1. */
  api_version: z.string().nullable(),
  /** Observed methods with lifecycle metadata (§9). Only observed or
   *  explicitly documented methods are facts. */
  methods: z.array(EndpointMethodObservationSchema),
  content_types: z.array(z.string()).max(32),
  authentication_observed: z.boolean(),
  identities_observed: z.array(z.string()).max(64),
  status: z.enum(ENDPOINT_STATUSES),
  discovery_source: z.enum(DISCOVERY_SOURCES),
  confidence_category: z.enum(CONFIDENCE_CATEGORIES),
  confidence: z.number().min(0).max(1),
  /** Bounded sample of distinct observed URLs (dedup evidence, §7). */
  observed_urls: z.array(z.string()).max(16),
  observation_count: z.number().int().min(0),
  signal_count: z.number().int().min(0),
  evidence_ids: z.array(z.string()).max(64),
  merged_into: z.string().nullable(),
  first_seen: z.string(),
  last_seen: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type EndpointRecord = z.infer<typeof EndpointRecordSchema>;

// ---------------------------------------------------------------------------
// Parameters (spec §14-§18).
// ---------------------------------------------------------------------------

export const SemanticCandidateSchema = z.object({
  semantic: z.enum(PARAMETER_SEMANTICS),
  confidence: z.number().min(0).max(1),
  reason: z.string().max(500),
});
export type SemanticCandidate = z.infer<typeof SemanticCandidateSchema>;

export const ParameterRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  endpoint_id: z.string().nullable(),
  /** Fingerprint over endpoint + location + name (idempotency, §111). */
  fingerprint: z.string(),
  name: z.string().max(256),
  location: z.enum(PARAMETER_LOCATIONS),
  /** Observed serialized type: string|number|boolean|null|array|object. */
  observed_type: z.string().nullable(),
  /** Bounded example values (sensitive values stored redacted, §115). */
  example_values: z.array(z.string().max(256)).max(8),
  value_characteristics: z.array(z.enum(VALUE_CHARACTERISTICS)).max(12),
  /** Name-based semantic candidates — never trusted blindly (§16). */
  semantic_candidates: z.array(SemanticCandidateSchema).max(4),
  identity_association: z.array(z.string()).max(32),
  is_sensitive: z.boolean(),
  confidence: z.number().min(0).max(1),
  observation_count: z.number().int().min(1),
  first_seen: z.string(),
  last_seen: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type ParameterRecord = z.infer<typeof ParameterRecordSchema>;

// ---------------------------------------------------------------------------
// Authorization matrix (spec §23, §98).
// ---------------------------------------------------------------------------

export const AuthorizationMatrixEntrySchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  endpoint_id: z.string(),
  /** null identity = ANONYMOUS (§20). */
  identity_id: z.string().nullable(),
  /** Normalized object reference, e.g. "order:381" (object-level, §98). */
  object_ref: z.string().nullable(),
  /** Operation (method-level action) when distinguishable. */
  action: z.string().nullable(),
  outcome: z.enum(ACCESS_OUTCOMES),
  status_code: z.number().int().nullable(),
  request_id: z.string().nullable(),
  evidence_ids: z.array(z.string()).max(32),
  observation_count: z.number().int().min(1),
  fingerprint: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type AuthorizationMatrixEntry = z.infer<typeof AuthorizationMatrixEntrySchema>;

// ---------------------------------------------------------------------------
// Workflows / states / transitions (spec §30-§35).
// ---------------------------------------------------------------------------

export const WorkflowRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  name: z.string().max(256),
  status: z.enum(WORKFLOW_STATUSES),
  required_identity: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  state_count: z.number().int().min(0),
  transition_count: z.number().int().min(0),
  evidence_ids: z.array(z.string()).max(64),
  created_at: z.string(),
  updated_at: z.string(),
});
export type WorkflowRecord = z.infer<typeof WorkflowRecordSchema>;

export const WorkflowStateRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  workflow_id: z.string(),
  name: z.string().max(128),
  /** How the state is detected (§31): url / response / dom / cookie. */
  detection: z.record(z.string(), z.unknown()),
  observed: z.boolean(),
  confidence: z.number().min(0).max(1),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type WorkflowStateRecord = z.infer<typeof WorkflowStateRecordSchema>;

export const WorkflowTransitionRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  workflow_id: z.string(),
  from_state_id: z.string().nullable(),
  to_state_id: z.string(),
  trigger_endpoint_id: z.string().nullable(),
  /** e.g. "POST /api/orders/381/confirm" (bounded, untrusted-derived). */
  trigger_summary: z.string().max(512),
  identity_id: z.string().nullable(),
  observation_kind: z.enum(TRANSITION_OBSERVATION_KINDS),
  confidence: z.number().min(0).max(1),
  occurrence_count: z.number().int().min(1),
  evidence_ids: z.array(z.string()).max(32),
  fingerprint: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type WorkflowTransitionRecord = z.infer<typeof WorkflowTransitionRecordSchema>;

// ---------------------------------------------------------------------------
// Data flows (spec §37-§41).
// ---------------------------------------------------------------------------

export const DataFlowEndpointSchema = z.object({
  kind: z.enum(DATA_FLOW_SOURCE_KINDS).or(z.enum(DATA_FLOW_SINK_KINDS)),
  name: z.string().max(256),
  endpoint_id: z.string().nullable(),
  page_url: z.string().max(2048).nullable(),
});
export type DataFlowEndpoint = z.infer<typeof DataFlowEndpointSchema>;

export const DataFlowRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  source: DataFlowEndpointSchema,
  transformations: z.array(z.string()).max(8),
  sink: DataFlowEndpointSchema,
  correlation: z.enum(CORRELATION_KINDS),
  confidence: z.number().min(0).max(1),
  evidence_ids: z.array(z.string()).max(32),
  fingerprint: z.string(),
  created_at: z.string(),
});
export type DataFlowRecord = z.infer<typeof DataFlowRecordSchema>;

// ---------------------------------------------------------------------------
// Security signals (spec §42-§43). Signals are not findings.
// ---------------------------------------------------------------------------

export const SecuritySignalRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  signal_type: z.enum(SIGNAL_TYPES),
  /** Where the signal came from (HTTP_RESPONSE, DOM, DIFFERENTIAL, ...). */
  source: z.string().max(64),
  endpoint_id: z.string().nullable(),
  parameter_id: z.string().nullable(),
  identity_ids: z.array(z.string()).max(16),
  object_ref: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  /** Bounded summary derived from untrusted target data (§115). */
  summary: z.string().max(2000),
  metadata: z.record(z.string(), z.unknown()),
  status: z.enum(SIGNAL_STATUSES),
  evidence_ids: z.array(z.string()).max(32),
  fingerprint: z.string(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type SecuritySignalRecord = z.infer<typeof SecuritySignalRecordSchema>;

// ---------------------------------------------------------------------------
// Object candidates (spec §19, §96-§97).
// ---------------------------------------------------------------------------

export const ObjectCandidateRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  name: z.string().max(128),
  kind: z.string().max(64),
  parameter_id: z.string().nullable(),
  endpoint_id: z.string().nullable(),
  example_values: z.array(z.string().max(128)).max(8),
  owner_identity_id: z.string().nullable(),
  /** Candidate lifecycle: which endpoints create/read/update/delete it. */
  lifecycle: z.record(z.string(), z.unknown()),
  confidence: z.number().min(0).max(1),
  observation_count: z.number().int().min(1),
  evidence_ids: z.array(z.string()).max(32),
  fingerprint: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  created_at: z.string(),
});
export type ObjectCandidateRecord = z.infer<typeof ObjectCandidateRecordSchema>;

// ---------------------------------------------------------------------------
// Attack-surface graph (spec §4-§5).
// ---------------------------------------------------------------------------

export const AttackNodeRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  node_type: z.enum(ATTACK_NODE_TYPES),
  /** Referenced record id when the node mirrors a persisted entity. */
  external_ref: z.string().nullable(),
  fingerprint: z.string(),
  label: z.string().max(512),
  metadata: z.record(z.string(), z.unknown()),
  confidence: z.number().min(0).max(1),
  first_seen: z.string(),
  last_seen: z.string(),
});
export type AttackNodeRecord = z.infer<typeof AttackNodeRecordSchema>;

export const AttackEdgeRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  source_node_id: z.string(),
  target_node_id: z.string(),
  relation: z.enum(ATTACK_EDGE_RELATIONS),
  metadata: z.record(z.string(), z.unknown()),
  confidence: z.number().min(0).max(1),
  created_at: z.string(),
});
export type AttackEdgeRecord = z.infer<typeof AttackEdgeRecordSchema>;

// ---------------------------------------------------------------------------
// Differential testing (spec §24-§28, §61).
// ---------------------------------------------------------------------------

export const DifferentialValueChangeSchema = z.object({
  path: z.string().max(512),
  baseline: z.string().max(256),
  candidate: z.string().max(256),
  volatile: z.boolean(),
});
export type DifferentialValueChange = z.infer<typeof DifferentialValueChangeSchema>;

export const DifferentialResultSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  test_id: z.string().nullable(),
  hypothesis_id: z.string().nullable(),
  baseline_request_id: z.string().nullable(),
  candidate_request_id: z.string().nullable(),
  baseline_identity: z.string().nullable(),
  candidate_identity: z.string().nullable(),
  summary: z.object({
    status_changed: z.boolean(),
    status_baseline: z.number().int().nullable(),
    status_candidate: z.number().int().nullable(),
    headers_changed: z.array(z.string().max(128)).max(64),
    schema_changed: z.boolean(),
    fields_added: z.array(z.string().max(256)).max(64),
    fields_removed: z.array(z.string().max(256)).max(64),
    values_changed: z.array(DifferentialValueChangeSchema).max(128),
    body_similarity: z.number().min(0).max(1),
    redirect_changed: z.boolean(),
    timing_changed: z.boolean(),
    volatile_fields: z.array(z.string().max(256)).max(64),
  }),
  detail: z.record(z.string(), z.unknown()),
  created_at: z.string(),
});
export type DifferentialResult = z.infer<typeof DifferentialResultSchema>;

// ---------------------------------------------------------------------------
// Verification (spec §72-§74).
// ---------------------------------------------------------------------------

export const VerificationCheckSchema = z.object({
  check: z.string().max(128),
  status: z.enum(VERIFICATION_CHECK_STATUSES),
  detail: z.string().max(1000),
  evidence_ids: z.array(z.string()).max(16),
});
export type VerificationCheck = z.infer<typeof VerificationCheckSchema>;

export const VerificationRecordSchema = z.object({
  id: z.string(),
  engagement_id: z.string(),
  hypothesis_id: z.string().nullable(),
  kind: z.string().max(64),
  /** Alternative explanations evaluated (§72, §74). */
  alternatives: z.array(
    z.object({
      explanation: z.string().max(500),
      refuted: z.boolean(),
      detail: z.string().max(1000),
    }),
  ).max(12),
  checklist: z.array(VerificationCheckSchema).max(16),
  status: z.enum(VERIFICATION_STATUSES),
  result: z.record(z.string(), z.unknown()),
  evidence_ids: z.array(z.string()).max(64),
  created_at: z.string(),
  completed_at: z.string().nullable(),
});
export type VerificationRecord = z.infer<typeof VerificationRecordSchema>;

// ---------------------------------------------------------------------------
// Hypothesis candidates + test candidates (spec §44-§47, §118).
// ---------------------------------------------------------------------------

export const HypothesisCandidateSchema = z.object({
  statement: z.string().min(1).max(2000),
  type: z.string().max(64),
  initial_confidence: z.number().min(0).max(1),
  priority: z.number().min(0).max(1),
  /** Evidence the hypothesis needs before promotion (§46). */
  required_evidence: z.array(z.string().max(500)).max(12),
  signal_id: z.string(),
  competing: z.boolean(),
  rationale: z.string().max(1000),
});
export type HypothesisCandidate = z.infer<typeof HypothesisCandidateSchema>;

export const TestCandidateSchema = z.object({
  hypothesis_id: z.string().nullable(),
  test_type: z.string().max(64),
  endpoint_id: z.string().nullable(),
  baseline_identity: z.string().nullable(),
  candidate_identity: z.string().nullable(),
  mutation_category: z.enum(MUTATION_CATEGORIES).nullable(),
  /** Base request to replay/mutate when available. */
  base_request_id: z.string().nullable(),
  mutations: z.array(HttpMutationSchema).max(16),
  expected_information_gain: z.number().min(0).max(1),
  estimated_cost: z.number().int().min(1).max(64),
  priority: z.number().min(0).max(1),
  fingerprint: z.string(),
  preconditions: z.object({
    scope_ok: z.boolean(),
    identity_available: z.boolean(),
    baseline_available: z.boolean(),
    duplicate_absent: z.boolean(),
  }),
  rationale: z.string().max(1000),
});
export type TestCandidate = z.infer<typeof TestCandidateSchema>;

// ---------------------------------------------------------------------------
// Leader security projection (spec §120) — compact, focused (§80).
// ---------------------------------------------------------------------------

export const SecurityProjectionSchema = z.object({
  attack_surface: z.object({
    endpoint_count: z.number().int().min(0),
    resource_family_count: z.number().int().min(0),
    identity_count: z.number().int().min(0),
    workflow_count: z.number().int().min(0),
    parameter_count: z.number().int().min(0),
    object_count: z.number().int().min(0),
    top_endpoints: z
      .array(
        z.object({
          id: z.string(),
          method_summary: z.string().max(256),
          canonical_path: z.string().max(512),
          status: z.string().max(32),
          priority: z.number().min(0).max(1),
        }),
      )
      .max(12),
  }),
  interesting: z
    .array(
      z.object({
        id: z.string(),
        signal_type: z.string().max(64),
        summary: z.string().max(500),
        confidence: z.number().min(0).max(1),
      }),
    )
    .max(12),
  active_hypotheses: z
    .array(
      z.object({
        id: z.string(),
        statement: z.string().max(500),
        confidence: z.number().min(0).max(1),
      }),
    )
    .max(12),
  recommended_tests: z.array(TestCandidateSchema).max(8),
});
export type SecurityProjection = z.infer<typeof SecurityProjectionSchema>;

/** Provider seam consumed by the Part 2 context builder (§120). */
export interface SecurityContextProvider {
  buildSecurityProjection(engagementId: string): Promise<SecurityProjection>;
}

// ---------------------------------------------------------------------------
// Focused attack-surface query (spec §80) — for workers via tools.
// ---------------------------------------------------------------------------

export const ReasoningQueryInputSchema = z
  .object({
    engagement_id: z.string().optional(),
    endpoint_id: z.string().nullable().default(null),
    hypothesis_id: z.string().nullable().default(null),
    signal_type: z.string().max(64).nullable().default(null),
  })
  .strict();
export type ReasoningQueryInput = z.infer<typeof ReasoningQueryInputSchema>;

export const ReasoningQueryResponseSchema = z.object({
  engagement_id: z.string(),
  endpoints: z.array(EndpointRecordSchema).max(16),
  parameters: z.array(ParameterRecordSchema).max(64),
  matrix: z.array(AuthorizationMatrixEntrySchema).max(64),
  signals: z.array(SecuritySignalRecordSchema).max(32),
  objects: z.array(ObjectCandidateRecordSchema).max(32),
  workflow_states: z.array(WorkflowStateRecordSchema).max(32),
  recent_differentials: z.array(DifferentialResultSchema).max(8),
  dead_ends: z.array(z.record(z.string(), z.unknown())).max(10),
});
export type ReasoningQueryResponse = z.infer<typeof ReasoningQueryResponseSchema>;

// ---------------------------------------------------------------------------
// Tool inputs/outputs (differential.compare, verification.evaluate).
// ---------------------------------------------------------------------------

export const DifferentialCompareInputSchema = z
  .object({
    engagement_id: z.string().optional(),
    baseline_request_id: z.string(),
    candidate_request_id: z.string(),
    hypothesis_id: z.string().nullable().default(null),
    test_id: z.string().nullable().default(null),
  })
  .strict();
export type DifferentialCompareInput = z.infer<typeof DifferentialCompareInputSchema>;

export const VerificationEvaluateInputSchema = z
  .object({
    engagement_id: z.string().optional(),
    hypothesis_id: z.string(),
  })
  .strict();
export type VerificationEvaluateInput = z.infer<typeof VerificationEvaluateInputSchema>;

export const VerificationEvaluateResponseSchema = z.object({
  verification: VerificationRecordSchema,
  /** Hypothesis effects applied by the bridge (promote/disprove), if any. */
  hypothesis_status: z.string().nullable(),
  finding_id: z.string().nullable(),
});
export type VerificationEvaluateResponse = z.infer<typeof VerificationEvaluateResponseSchema>;

// ---------------------------------------------------------------------------
// Evidence strength classification (spec §70).
// ---------------------------------------------------------------------------

export const EvidenceStrengthAssessmentSchema = z.object({
  level: z.enum(EVIDENCE_STRENGTH_LEVELS),
  reasons: z.array(z.string().max(500)).max(8),
});
export type EvidenceStrengthAssessment = z.infer<typeof EvidenceStrengthAssessmentSchema>;

// ---------------------------------------------------------------------------
// API response envelopes.
// ---------------------------------------------------------------------------

export const EndpointListResponseSchema = z.object({
  items: z.array(EndpointRecordSchema),
  total: z.number().int().min(0),
});
export type EndpointListResponse = z.infer<typeof EndpointListResponseSchema>;

export const ParameterListResponseSchema = z.object({
  items: z.array(ParameterRecordSchema),
  total: z.number().int().min(0),
});
export type ParameterListResponse = z.infer<typeof ParameterListResponseSchema>;

export const SignalListResponseSchema = z.object({
  items: z.array(SecuritySignalRecordSchema),
  total: z.number().int().min(0),
});
export type SignalListResponse = z.infer<typeof SignalListResponseSchema>;

export const AuthorizationMatrixResponseSchema = z.object({
  items: z.array(AuthorizationMatrixEntrySchema),
  total: z.number().int().min(0),
});
export type AuthorizationMatrixResponse = z.infer<typeof AuthorizationMatrixResponseSchema>;

export const WorkflowListResponseSchema = z.object({
  items: z.array(WorkflowRecordSchema),
  total: z.number().int().min(0),
});
export type WorkflowListResponse = z.infer<typeof WorkflowListResponseSchema>;

export const WorkflowDetailResponseSchema = z.object({
  workflow: WorkflowRecordSchema,
  states: z.array(WorkflowStateRecordSchema),
  transitions: z.array(WorkflowTransitionRecordSchema),
});
export type WorkflowDetailResponse = z.infer<typeof WorkflowDetailResponseSchema>;

export const DataFlowListResponseSchema = z.object({
  items: z.array(DataFlowRecordSchema),
  total: z.number().int().min(0),
});
export type DataFlowListResponse = z.infer<typeof DataFlowListResponseSchema>;

export const ObjectCandidateListResponseSchema = z.object({
  items: z.array(ObjectCandidateRecordSchema),
  total: z.number().int().min(0),
});
export type ObjectCandidateListResponse = z.infer<typeof ObjectCandidateListResponseSchema>;

export const AttackGraphResponseSchema = z.object({
  nodes: z.array(AttackNodeRecordSchema).max(2000),
  edges: z.array(AttackEdgeRecordSchema).max(4000),
  truncated: z.boolean(),
});
export type AttackGraphResponse = z.infer<typeof AttackGraphResponseSchema>;

export const DifferentialListResponseSchema = z.object({
  items: z.array(DifferentialResultSchema),
  total: z.number().int().min(0),
});
export type DifferentialListResponse = z.infer<typeof DifferentialListResponseSchema>;

export const VerificationListResponseSchema = z.object({
  items: z.array(VerificationRecordSchema),
  total: z.number().int().min(0),
});
export type VerificationListResponse = z.infer<typeof VerificationListResponseSchema>;

export const TestCandidateListResponseSchema = z.object({
  items: z.array(TestCandidateSchema),
  total: z.number().int().min(0),
});
export type TestCandidateListResponse = z.infer<typeof TestCandidateListResponseSchema>;

export const ReasoningIngestResponseSchema = z.object({
  processed: z.number().int().min(0),
  created_endpoints: z.number().int().min(0),
  updated_endpoints: z.number().int().min(0),
  created_parameters: z.number().int().min(0),
  matrix_entries: z.number().int().min(0),
  signals_created: z.number().int().min(0),
  failures: z.number().int().min(0),
});
export type ReasoningIngestResponse = z.infer<typeof ReasoningIngestResponseSchema>;

export const ReasoningStatusResponseSchema = z.object({
  counts: z.object({
    endpoints: z.number().int().min(0),
    parameters: z.number().int().min(0),
    signals: z.number().int().min(0),
    signals_new: z.number().int().min(0),
    objects: z.number().int().min(0),
    workflows: z.number().int().min(0),
    data_flows: z.number().int().min(0),
    matrix_entries: z.number().int().min(0),
    graph_nodes: z.number().int().min(0),
    graph_edges: z.number().int().min(0),
    differentials: z.number().int().min(0),
    verifications: z.number().int().min(0),
    processor_failures: z.number().int().min(0),
  }),
  recent_failures: z
    .array(
      z.object({
        id: z.string(),
        processor: z.string(),
        event_type: z.string().nullable(),
        error: z.string().max(500),
        created_at: z.string(),
      }),
    )
    .max(10),
});
export type ReasoningStatusResponse = z.infer<typeof ReasoningStatusResponseSchema>;
