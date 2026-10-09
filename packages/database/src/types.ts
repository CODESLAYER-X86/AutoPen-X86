/** Domain record types returned by repositories (snake_case kept for API fidelity). */
import type {
  EngagementMode,
  EngagementStatus,
  IdentityType,
  SessionType,
  SessionStatus,
  TargetType,
  AssetType,
  EventType,
  AgentRunStatus,
  DecisionType,
  TaskStatus,
  TaskType,
  WorkerType,
  HypothesisStatus,
  HypothesisType,
  TestStatus,
  FindingStatus,
  TokenPurpose,
  // Part 4 — Security Reasoning Engine enums.
  EndpointStatus,
  DiscoverySource,
  ConfidenceCategory,
  ParameterLocation,
  ValueCharacteristic,
  ParameterSemantic,
  AccessOutcome,
  SignalType,
  SignalStatus,
  WorkflowStatus,
  TransitionObservationKind,
  AttackNodeType,
  AttackEdgeRelation,
  CorrelationKind,
  VerificationStatus,
  VerificationCheckStatus,
  // Part 5 — Knowledge & Web Research enums.
  KnowledgeSourceType,
  KnowledgeTrustLevel,
  KnowledgeDocumentType,
  KnowledgeUpdateStrategy,
  KnowledgeIngestionStatus,
  KnowledgeChunkKind,
  SecurityTaxonomyCategory,
  KnowledgeReferenceKind,
  ResearchMode,
  ResearchStatus,
  // Part 6 — Autonomous Pentest & CTF Engine enums.
  AutonomousPhase,
  AutonomousMode,
  BranchStatus,
  CtfStatus,
  CtfClueSource,
  CtfClueStatus,
  FlagConditionStatus,
  EngineRiskLevel,
  ApprovalDecision,
  TestResultOutcome,
  ConfidenceLevel,
} from '@aegis/shared';
import type { Iso8601, JsonRecord } from '@aegis/shared';

export interface UserRecord {
  id: string;
  email: string;
  name: string;
  password_hash: string;
  role: string;
  last_login_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface ProjectRecord {
  id: string;
  owner_id: string;
  name: string;
  description: string;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface EngagementRecord {
  id: string;
  project_id: string;
  name: string;
  mode: EngagementMode;
  status: EngagementStatus;
  description: string;
  started_at: Iso8601 | null;
  completed_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface TargetRecord {
  id: string;
  engagement_id: string;
  type: TargetType;
  value: string;
  label: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface ScopeRecord {
  id: string;
  engagement_id: string;
  allowed_hosts: string[];
  allowed_domains: string[];
  allowed_ports: number[];
  allowed_schemes: string[];
  excluded_hosts: string[];
  excluded_paths: string[];
  rate_limit: number | null;
  concurrency_limit: number | null;
  destructive_actions_allowed: boolean;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface AssetRecord {
  id: string;
  engagement_id: string;
  type: AssetType;
  value: string;
  label: string | null;
  parent_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface IdentityRecord {
  id: string;
  engagement_id: string;
  name: string;
  role: string;
  type: IdentityType;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

/** TARGET-side session (cookies/JWTs of the application under test). */
export interface SessionRecord {
  id: string;
  identity_id: string;
  type: SessionType;
  status: SessionStatus;
  metadata: JsonRecord;
  secret_reference: string;
  created_at: Iso8601;
  expires_at: Iso8601 | null;
  updated_at: Iso8601;
  /** Part 3: why the session left ACTIVE (spec §27). */
  status_reason: string | null;
  /** Part 3: engagement scoping. */
  engagement_id: string | null;
}

/** PLATFORM-side authentication session (UI/API login). */
export interface AuthSessionRecord {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: Iso8601;
  expires_at: Iso8601;
  revoked_at: Iso8601 | null;
}

export interface EventRecord {
  id: string;
  type: EventType;
  engagement_id: string | null;
  task_id: string | null;
  trace_id: string | null;
  actor_id: string | null;
  payload: JsonRecord;
  occurred_at: Iso8601;
  dedup_key: string | null;
}

export interface AuditRecord {
  id: string;
  actor_user_id: string | null;
  action: string;
  resource: string;
  resource_id: string | null;
  engagement_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
}

export interface EvidenceRecord {
  id: string;
  engagement_id: string;
  type: string;
  source: string;
  content_reference: string;
  sha256: string;
  parent_id: string | null;
  task_id: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Part 2 — Agent Operating System records (spec Part 2 §2).
// ---------------------------------------------------------------------------

export interface AgentRunRecord {
  id: string;
  engagement_id: string;
  status: AgentRunStatus;
  reason: string | null;
  strategy_version: number | null;
  leader_model: string;
  worker_model: string;
  metrics: JsonRecord;
  started_at: Iso8601 | null;
  ended_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface AgentDecisionRecord {
  id: string;
  run_id: string;
  engagement_id: string;
  cycle: number;
  input_state_hash: string;
  decision_type: DecisionType;
  reasoning_summary: string;
  payload: JsonRecord;
  validation_status: 'PENDING' | 'VALID' | 'REJECTED' | 'FAILED';
  rejection_code: string | null;
  rejection_details: JsonRecord | null;
  cycle_outcome: JsonRecord | null;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  created_at: Iso8601;
}

export interface HypothesisRecord {
  id: string;
  engagement_id: string;
  type: HypothesisType;
  statement: string;
  status: HypothesisStatus;
  confidence: number;
  priority: number;
  source: string;
  parent_hypothesis_id: string | null;
  created_at: Iso8601;
  updated_at: Iso8601;
  confirmed_at: Iso8601 | null;
  disproved_at: Iso8601 | null;
}

export interface HypothesisLinkRecord {
  id: string;
  hypothesis_id: string;
  ref_type: 'OBSERVATION' | 'TEST' | 'EVIDENCE';
  ref_id: string;
  created_at: Iso8601;
}

export interface ObservationRecord {
  id: string;
  engagement_id: string;
  task_id: string | null;
  hypothesis_id: string | null;
  type: string;
  description: string;
  confidence: number;
  evidence_ids: string[];
  metadata: JsonRecord;
  created_at: Iso8601;
}

export interface TaskRecord {
  id: string;
  engagement_id: string;
  run_id: string | null;
  decision_id: string | null;
  hypothesis_id: string | null;
  type: TaskType;
  objective: string;
  worker_type: WorkerType;
  status: TaskStatus;
  priority: number;
  expected_information_gain: number | null;
  depends_on: string[];
  allowed_tools: string[];
  constraints: JsonRecord;
  inputs: JsonRecord;
  result: JsonRecord | null;
  attempts: number;
  max_attempts: number;
  failure_code: string | null;
  failure_reason: string | null;
  idempotency_key: string;
  created_at: Iso8601;
  updated_at: Iso8601;
  started_at: Iso8601 | null;
  completed_at: Iso8601 | null;
  /** Part 6 §55: lease ownership of the executing engine instance. */
  lease_expires_at: Iso8601 | null;
  leased_by: string | null;
  heartbeat_at: Iso8601 | null;
}

export interface TaskAttemptRecord {
  id: string;
  task_id: string;
  engagement_id: string;
  attempt: number;
  worker_type: WorkerType;
  worker_model: string;
  status: string;
  output: JsonRecord | null;
  error_code: string | null;
  error_message: string | null;
  tool_calls: number;
  network_requests: number;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  started_at: Iso8601;
  ended_at: Iso8601 | null;
}

export interface TestRecord {
  id: string;
  engagement_id: string;
  task_id: string | null;
  hypothesis_id: string | null;
  test_type: string;
  target: string;
  identity: string | null;
  mutation_summary: string | null;
  fingerprint: string;
  status: TestStatus;
  result_summary: string | null;
  created_at: Iso8601;
  /** Part 6 §60: experimental verdict. */
  result: TestResultOutcome | null;
  expected_signal: string | null;
  actual_signal: string | null;
  mutation: JsonRecord | null;
}

export interface DeadEndRecord {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  description: string;
  tests: string[];
  reason: string;
  created_at: Iso8601;
}

export interface StrategyRecord {
  id: string;
  engagement_id: string;
  run_id: string | null;
  version: number;
  summary: string;
  focus: string;
  reason: string;
  created_at: Iso8601;
}

export interface FindingRecord {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  title: string;
  description: string;
  severity: string;
  status: FindingStatus;
  evidence_ids: string[];
  created_at: Iso8601;
  updated_at: Iso8601;
  /** Part 6 §28/§58: confidence model (NOT severity) + rich linkage. */
  category: string | null;
  confidence: number | null;
  confidence_level: ConfidenceLevel | null;
  confidence_reasons: string[];
  impact: string | null;
  remediation: string | null;
  verification_ids: string[];
  target_refs: string[];
  affected_endpoints: string[];
  affected_identities: string[];
  mode: string;
  /** Part 7 §38: retest state. */
  retest_state: 'NOT_RETESTED' | 'OPEN' | 'FIXED' | 'PARTIALLY_FIXED' | 'STILL_PRESENT';
  /** Part 7 §18: deterministic CVSS representation (null until computed). */
  cvss: {
    version: string;
    vector: string;
    base_score: number;
    temporal_score: number | null;
    environmental_score: number | null;
    base_severity: string;
  } | null;
  severity_source: 'CVSS_CALCULATOR' | 'HUMAN_OVERRIDE';
  /** Part 7 §19: deduplication key + duplicate linkage. */
  dedup_key: string | null;
  duplicate_of: string | null;
  /** Part 7 §6: structured observed/expected behavior. */
  observed_behavior: string | null;
  expected_behavior: string | null;
}

/** Part 7 §5: auditable finding lifecycle transition. */
export interface FindingLifecycleEventRecord {
  id: string;
  finding_id: string;
  engagement_id: string;
  from_status: string;
  to_status: string;
  reason: string;
  actor: 'ENGINE' | 'HUMAN';
  created_at: Iso8601;
}

/** Part 7 §70: per-finding evidence quality level. */
export interface FindingEvidenceQualityRecord {
  id: string;
  finding_id: string;
  engagement_id: string;
  evidence_id: string;
  quality: 'RAW' | 'EXTRACTED' | 'CORRELATED' | 'ANALYZED' | 'VERIFIED';
  note: string | null;
  created_at: Iso8601;
}

/** Part 7 §8: verification plan. */
export interface VerificationPlanRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  strategies: string[];
  controls: string[];
  expected_result: JsonRecord;
  required_evidence: Array<{ kind: string; description: string; required: boolean }>;
  sufficiency: {
    sufficient: boolean;
    missing: string[];
    dimensions: Record<string, boolean>;
    note: string;
  };
  status: 'PLANNED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';
  result_id: string | null;
  error: string | null;
  created_at: Iso8601;
  completed_at: Iso8601 | null;
}

/** Part 7 §10: alternative explanation test. */
export interface AlternativeExplanationRecord {
  id: string;
  label: string;
  description: string;
  refuted: boolean;
  refutation: string | null;
  evidence_ids: string[];
}

/** Part 7 §14: verification result. */
export interface VerificationResultRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  plan_id: string;
  status: 'VERIFIED' | 'REJECTED' | 'INCONCLUSIVE';
  confidence: number;
  supporting_evidence_ids: string[];
  contradictory_evidence_ids: string[];
  reproduced: boolean;
  alternative_explanations: AlternativeExplanationRecord[];
  reasoning_summary: string;
  completed_at: Iso8601;
}

/** Part 7 §12: controlled reproduction plan. */
export interface ReproductionPlanRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  prerequisites: string[];
  steps: Array<{ kind: string; reference: string; description: string }>;
  expected_signals: Array<{ signal: string; source: string }>;
  created_at: Iso8601;
}

/** Part 7 §17-§18: severity assessment. */
export interface SeverityAssessmentRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  input: JsonRecord;
  severity: string;
  source: 'CVSS_CALCULATOR' | 'HUMAN_OVERRIDE';
  cvss: {
    version: string;
    vector: string;
    base_score: number;
    temporal_score: number | null;
    environmental_score: number | null;
    base_severity: string;
  };
  created_at: Iso8601;
}

/** Part 7 §67: human review. */
export interface FindingReviewRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  agent_status: string;
  agent_confidence: number | null;
  decision: string;
  reviewer: string;
  reason: string;
  agent_human_disagreement: boolean;
  resulting_status: string;
  metadata: JsonRecord;
  created_at: Iso8601;
}

/** Part 7 §37: retest record. */
export interface RetestRecord {
  id: string;
  engagement_id: string;
  finding_id: string;
  status: 'NOT_RETESTED' | 'OPEN' | 'FIXED' | 'PARTIALLY_FIXED' | 'STILL_PRESENT';
  outcome: 'FIXED' | 'PARTIALLY_FIXED' | 'STILL_PRESENT' | null;
  verification_id: string | null;
  note: string | null;
  requested_by: string;
  requested_at: Iso8601;
  completed_at: Iso8601 | null;
}

/** Part 7 §34: report claim with evidence mapping. */
export interface ReportClaimRecord {
  id: string;
  finding_id: string;
  text: string;
  evidence_ids: string[];
  confidence: number;
  support: 'SUPPORTED' | 'BROADER_THAN_EVIDENCE' | 'UNSUPPORTED';
  revision_of: string | null;
}

/** Part 7 §65: report validation issue. */
export interface ReportValidationIssueRecord {
  code: string;
  message: string;
  severity: 'ERROR' | 'WARNING';
  finding_id: string | null;
  claim_id: string | null;
}

/** Part 7 §25: generated report. */
export interface ReportRecord {
  id: string;
  engagement_id: string;
  type: 'EXECUTIVE' | 'TECHNICAL' | 'MACHINE' | 'RETEST' | 'CTF_SOLUTION';
  status: 'GENERATING' | 'VALIDATED' | 'REJECTED' | 'EXPORTED';
  version: number;
  title: string;
  manifest: {
    report_hash: string;
    evidence_hashes: Record<string, string>;
    finding_ids: string[];
    generation_config: JsonRecord;
  } | null;
  claims: ReportClaimRecord[];
  validation_issues: ReportValidationIssueRecord[];
  content: JsonRecord;
  redactions: Array<{ location: string; rule: string }>;
  generated_by: string;
  generated_at: Iso8601;
}

/** Part 7 §63: rendered export artifact. */
export interface ReportExportRecord {
  id: string;
  report_id: string;
  engagement_id: string;
  format: 'JSON' | 'HTML' | 'MARKDOWN' | 'PDF';
  byte_size: number;
  sha256: string;
  content_reference: string;
  created_at: Iso8601;
}

/** Part 7 §41: ground-truth finding (hidden from the agent). */
export interface EvaluationExpectedFindingRecord {
  id: string;
  scenario_id: string;
  endpoint: string;
  finding_category: string;
  severity: string;
  verification_required: boolean;
  match_tokens: string[];
  description: string;
}

/** Part 7 §39: scenario definition. */
export interface EvaluationScenarioRecord {
  id: string;
  name: string;
  kind: string;
  description: string;
  fixture: string;
  expected_findings: EvaluationExpectedFindingRecord[];
  expected_observations: string[];
  expected_hypotheses: string[];
  expected_stop_condition: string | null;
  safety_expectations: Array<{ kind: string; detail: string }>;
  version: number;
  created_at: Iso8601;
}

/** Part 7 §59: evaluation run. */
export interface EvaluationRunRecord {
  id: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'STOPPED';
  config: JsonRecord;
  started_by: string;
  started_at: Iso8601;
  completed_at: Iso8601 | null;
  error: string | null;
  is_golden: boolean;
  golden_reference: string | null;
}

/** Part 7 §59: queryable metric row. */
export interface EvaluationMetricRecord {
  id: string;
  run_id: string;
  scenario_id: string | null;
  metric: string;
  scope: string;
  value: number;
  unit: string;
  details: JsonRecord;
}

/** Part 7 §59: evaluation event row. */
export interface EvaluationEventRecord {
  id: string;
  run_id: string;
  scenario_id: string | null;
  type: string;
  description: string;
  occurred_at: Iso8601;
  metadata: JsonRecord;
}

/** Part 7 §59: observed finding match. */
export interface EvaluationObservedFindingRecord {
  id: string;
  run_id: string;
  scenario_id: string;
  expected_finding_id: string | null;
  finding_id: string;
  outcome: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE' | 'DUPLICATE';
  matched_tokens: string[];
  category: string;
}

/** Part 7 §59: model config snapshot. */
export interface EvaluationModelConfigRecord {
  id: string;
  run_id: string;
  label: string;
  strategic_model: string;
  tactical_model: string;
  prompt_versions: JsonRecord;
  tool_versions: JsonRecord;
  knowledge_index_version: string | null;
  budget: JsonRecord;
  random_seed: number | null;
  agent_version: string;
  created_at: Iso8601;
}

/** Part 7 §88-§89: regression check. */
export interface RegressionCheckRecord {
  id: string;
  run_id: string;
  baseline_run_id: string;
  verdict: 'PASS' | 'FAIL' | 'WARN';
  thresholds: JsonRecord;
  deltas: JsonRecord;
  failures: Array<{
    metric: string;
    baseline: number;
    current: number;
    delta: number;
    threshold: number;
    direction: 'MUST_NOT_FALL' | 'MUST_NOT_RISE' | 'MUST_BE_ZERO';
  }>;
  checked_at: Iso8601;
}

export interface AgentMessageRecord {
  id: string;
  engagement_id: string;
  run_id: string | null;
  task_id: string | null;
  channel: 'LEADER' | 'WORKER';
  direction: 'OUTBOUND' | 'INBOUND';
  role: 'system' | 'user' | 'assistant';
  content: string;
  untrusted_bytes: number;
  metadata: JsonRecord;
  input_tokens: number | null;
  output_tokens: number | null;
  created_at: Iso8601;
}

export interface ModelCallRecord {
  id: string;
  engagement_id: string;
  run_id: string | null;
  task_id: string | null;
  decision_id: string | null;
  role: 'strategic' | 'tactical';
  purpose: TokenPurpose;
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  duration_ms: number | null;
  status: 'COMPLETED' | 'FAILED';
  error_code: string | null;
  created_at: Iso8601;
}

export interface EngagementBudgetRecord {
  id: string;
  engagement_id: string;
  max_duration_seconds: number | null;
  max_network_requests: number | null;
  max_concurrent_requests: number | null;
  max_browser_contexts: number | null;
  max_model_calls: number | null;
  max_model_tokens: number | null;
  max_storage_bytes: number | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface EngagementUsageRecord {
  engagement_id: string;
  network_requests: number;
  concurrent_requests: number;
  browser_contexts: number;
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  storage_bytes: number;
  tool_calls: number;
  updated_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Part 4 — Security Reasoning Engine records (spec Part 4 §5-§43).
// ---------------------------------------------------------------------------

export interface EndpointMethodRecord {
  method: string;
  observation_count: number;
  identity_ids: string[];
  first_seen: Iso8601;
  last_seen: Iso8601;
}

export interface EndpointRecord {
  id: string;
  engagement_id: string;
  fingerprint: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  canonical_path: string;
  canonical_confidence: number;
  resource_family: string | null;
  api_version: string | null;
  methods: EndpointMethodRecord[];
  content_types: string[];
  authentication_observed: boolean;
  identities_observed: string[];
  status: EndpointStatus;
  discovery_source: DiscoverySource;
  confidence_category: ConfidenceCategory;
  confidence: number;
  observed_urls: string[];
  observation_count: number;
  signal_count: number;
  evidence_ids: string[];
  merged_into: string | null;
  first_seen: Iso8601;
  last_seen: Iso8601;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface SemanticCandidateRecord {
  semantic: ParameterSemantic;
  confidence: number;
  reason: string;
}

export interface ParameterRecord {
  id: string;
  engagement_id: string;
  endpoint_id: string | null;
  fingerprint: string;
  name: string;
  location: ParameterLocation;
  observed_type: string | null;
  example_values: string[];
  value_characteristics: ValueCharacteristic[];
  semantic_candidates: SemanticCandidateRecord[];
  identity_association: string[];
  is_sensitive: boolean;
  confidence: number;
  observation_count: number;
  first_seen: Iso8601;
  last_seen: Iso8601;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface AuthorizationMatrixRecord {
  id: string;
  engagement_id: string;
  endpoint_id: string;
  identity_id: string | null;
  object_ref: string | null;
  action: string | null;
  outcome: AccessOutcome;
  status_code: number | null;
  request_id: string | null;
  evidence_ids: string[];
  observation_count: number;
  fingerprint: string;
  first_seen: Iso8601;
  last_seen: Iso8601;
}

export interface WorkflowRecord {
  id: string;
  engagement_id: string;
  name: string;
  status: WorkflowStatus;
  required_identity: string | null;
  confidence: number;
  state_count: number;
  transition_count: number;
  evidence_ids: string[];
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface WorkflowStateRecord {
  id: string;
  engagement_id: string;
  workflow_id: string;
  name: string;
  detection: JsonRecord;
  observed: boolean;
  confidence: number;
  first_seen: Iso8601;
  last_seen: Iso8601;
}

export interface WorkflowTransitionRecord {
  id: string;
  engagement_id: string;
  workflow_id: string;
  from_state_id: string | null;
  to_state_id: string;
  trigger_endpoint_id: string | null;
  trigger_summary: string;
  identity_id: string | null;
  observation_kind: TransitionObservationKind;
  confidence: number;
  occurrence_count: number;
  evidence_ids: string[];
  fingerprint: string;
  first_seen: Iso8601;
  last_seen: Iso8601;
}

export interface DataFlowRecord {
  id: string;
  engagement_id: string;
  source: JsonRecord;
  transformations: string[];
  sink: JsonRecord;
  correlation: CorrelationKind;
  confidence: number;
  evidence_ids: string[];
  fingerprint: string;
  created_at: Iso8601;
}

export interface SecuritySignalRecord {
  id: string;
  engagement_id: string;
  signal_type: SignalType;
  source: string;
  endpoint_id: string | null;
  parameter_id: string | null;
  identity_ids: string[];
  object_ref: string | null;
  confidence: number;
  summary: string;
  metadata: JsonRecord;
  status: SignalStatus;
  evidence_ids: string[];
  fingerprint: string;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface ObjectCandidateRecord {
  id: string;
  engagement_id: string;
  name: string;
  kind: string;
  parameter_id: string | null;
  endpoint_id: string | null;
  example_values: string[];
  owner_identity_id: string | null;
  lifecycle: JsonRecord;
  confidence: number;
  observation_count: number;
  evidence_ids: string[];
  fingerprint: string;
  first_seen: Iso8601;
  last_seen: Iso8601;
  created_at: Iso8601;
}

export interface AttackNodeRecord {
  id: string;
  engagement_id: string;
  node_type: AttackNodeType;
  external_ref: string | null;
  fingerprint: string;
  label: string;
  metadata: JsonRecord;
  confidence: number;
  first_seen: Iso8601;
  last_seen: Iso8601;
}

export interface AttackEdgeRecord {
  id: string;
  engagement_id: string;
  source_node_id: string;
  target_node_id: string;
  relation: AttackEdgeRelation;
  metadata: JsonRecord;
  confidence: number;
  created_at: Iso8601;
}

export interface DifferentialResultRecord {
  id: string;
  engagement_id: string;
  test_id: string | null;
  hypothesis_id: string | null;
  baseline_request_id: string | null;
  candidate_request_id: string | null;
  baseline_identity: string | null;
  candidate_identity: string | null;
  summary: JsonRecord;
  detail: JsonRecord;
  created_at: Iso8601;
}

export interface VerificationCheckRecord {
  check: string;
  status: VerificationCheckStatus;
  detail: string;
  evidence_ids: string[];
}

export interface VerificationAlternativeRecord {
  explanation: string;
  refuted: boolean;
  detail: string;
}

export interface VerificationRecord {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  kind: string;
  alternatives: VerificationAlternativeRecord[];
  checklist: VerificationCheckRecord[];
  status: VerificationStatus;
  result: JsonRecord;
  evidence_ids: string[];
  created_at: Iso8601;
  completed_at: Iso8601 | null;
}

export interface ReasoningFailureRecord {
  id: string;
  engagement_id: string;
  processor: string;
  event_id: string | null;
  event_type: string | null;
  error: JsonRecord;
  retry_count: number;
  status: 'NEW' | 'RESOLVED' | 'SKIPPED';
  created_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Part 5 — Knowledge & Web Research records (spec Part 5 §5-§9, §43, §57,
// §71, §85, §95).
// ---------------------------------------------------------------------------

export interface KnowledgeCrawlPolicyRecord {
  allowed_domains: string[];
  blocked_domains: string[];
  entry_paths: string[];
  respect_robots: boolean;
}

export interface KnowledgeSourceRecord {
  id: string;
  name: string;
  type: KnowledgeSourceType;
  base_url: string;
  trust_level: KnowledgeTrustLevel;
  enabled: boolean;
  update_strategy: KnowledgeUpdateStrategy;
  crawl_policy: KnowledgeCrawlPolicyRecord;
  license_notes: string | null;
  last_synced: Iso8601 | null;
  configuration: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface KnowledgeDocumentMetadataRecord {
  author?: string | null;
  language?: string | null;
  technologies?: string[];
  cve_refs?: string[];
  cwe_refs?: string[];
  owasp_refs?: string[];
  http_methods?: string[];
  protocols?: string[];
  security_categories?: SecurityTaxonomyCategory[];
}

export interface KnowledgeCtfRecord {
  challenge_name: string;
  event: string | null;
  year: number | null;
  category: string | null;
  platform: string | null;
  difficulty: string | null;
  description: string;
  technique: string | null;
  solution_summary: string | null;
}

export interface KnowledgeDocumentRecord {
  id: string;
  source_id: string;
  title: string;
  canonical_url: string;
  content_hash: string;
  document_type: KnowledgeDocumentType;
  trust_level: KnowledgeTrustLevel;
  version: number;
  published_at: Iso8601 | null;
  retrieved_at: Iso8601;
  updated_at: Iso8601;
  ingestion_status: KnowledgeIngestionStatus;
  ingestion_error: string | null;
  metadata: KnowledgeDocumentMetadataRecord;
  artifact_ref: string | null;
  artifact_hash: string | null;
  chunk_count: number;
  ctf: KnowledgeCtfRecord | null;
  is_latest: boolean;
  superseded_by: string | null;
}

export interface KnowledgeChunkRecord {
  id: string;
  document_id: string;
  heading: string | null;
  heading_path: string[];
  section: string | null;
  content: string;
  token_estimate: number;
  kind: KnowledgeChunkKind;
  code_language: string | null;
  content_hash: string;
  parent_chunk_id: string | null;
  created_at: Iso8601;
}

export interface KnowledgeEmbeddingRecord {
  chunk_id: string;
  embedding: number[];
  embedding_model: string;
  embedding_version: number;
  dimension: number;
  content_hash: string;
  created_at: Iso8601;
}

export interface SecurityTechniqueRecord {
  id: string;
  name: string;
  category: SecurityTaxonomyCategory;
  description: string;
  preconditions: string[];
  signals: string[];
  test_patterns: string[];
  verification_patterns: string[];
  false_positive_conditions: string[];
  source_ids: string[];
  confidence: number;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface KnowledgeReferenceRecord {
  id: string;
  document_id: string | null;
  chunk_id: string | null;
  technique_id: string | null;
  hypothesis_id: string | null;
  kind: KnowledgeReferenceKind;
  value: string;
  context: string | null;
  created_at: Iso8601;
}

export interface KnowledgeQueryRecord {
  id: string;
  engagement_id: string | null;
  hypothesis_id: string | null;
  requested_by: string;
  query: string;
  categories: string[];
  technologies: string[];
  mode: ResearchMode;
  cache_key: string | null;
  cache_hit: boolean;
  result_count: number;
  tokens_estimate: number;
  created_at: Iso8601;
}

export interface KnowledgeResultRecord {
  id: string;
  query_id: string;
  rank: number;
  chunk_id: string | null;
  technique_id: string | null;
  relevance: number;
  keyword_score: number;
  semantic_score: number;
  trust_score: number;
  freshness_score: number;
  final_score: number;
  included: boolean;
  created_at: Iso8601;
}

export interface ResearchTaskRecord {
  id: string;
  engagement_id: string | null;
  requested_by: string;
  question: string;
  hypothesis: string | null;
  required_evidence: string[];
  source_constraints: string[];
  mode: ResearchMode;
  status: ResearchStatus;
  max_sources: number;
  max_tokens: number;
  deadline_ms: number;
  started_at: Iso8601 | null;
  completed_at: Iso8601 | null;
  error: string | null;
  result: JsonRecord | null;
  tokens_consumed: number;
  created_at: Iso8601;
}

export interface ResearchSourceRecord {
  id: string;
  research_task_id: string;
  document_id: string | null;
  url: string;
  domain: string;
  trust_level: KnowledgeTrustLevel;
  rank: number;
  selected: boolean;
  fetch_status: string | null;
  fetched_bytes: number;
  fetched_at: Iso8601 | null;
  reason: string | null;
  created_at: Iso8601;
}

export interface KnowledgeVersionRecord {
  id: string;
  embedding_model: string;
  embedding_version: number;
  chunker_min_tokens: number;
  chunker_max_tokens: number;
  dimension: number;
  active: boolean;
  note: string | null;
  created_at: Iso8601;
}

// ---------------------------------------------------------------------------
// Part 6 — Autonomous Pentest & CTF Engine records (spec Part 6 §6, §29-§31,
// §48-§49, §58, §65, §79).
// ---------------------------------------------------------------------------

export interface AutonomousEngineStateRecord {
  id: string;
  engagement_id: string;
  phase: AutonomousPhase;
  mode: AutonomousMode;
  waiting_reason: string | null;
  strategy_summary: string | null;
  replan_count: number;
  cycle_count: number;
  last_replan_trigger: string | null;
  knowledge_query_repeats: number;
  engine_instance_id: string | null;
  stop_reason: string | null;
  started_at: Iso8601 | null;
  finished_at: Iso8601 | null;
  last_transition_at: Iso8601;
  created_at: Iso8601;
  version: number;
}

export interface ReasoningBranchRecord {
  id: string;
  engagement_id: string;
  parent_branch_id: string | null;
  origin: string;
  origin_ref: string | null;
  focus: string;
  hypothesis_ids: string[];
  score: number;
  status: BranchStatus;
  pruned_reason: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface CtfContextRecord {
  id: string;
  engagement_id: string;
  title: string;
  description: string;
  hints: string[];
  flag_format: string | null;
  status: CtfStatus;
  flag_value: string | null;
  flag_evidence_id: string | null;
  solved_at: Iso8601 | null;
  analysis: JsonRecord;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface CtfClueInterpretation {
  concept: string;
  confidence: number;
  rationale: string;
}

export interface CtfClueRecord {
  id: string;
  engagement_id: string;
  source: CtfClueSource;
  text_content: string;
  interpretations: CtfClueInterpretation[];
  branch_id: string | null;
  status: CtfClueStatus;
  dead_end_reason: string | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface FlagConditionRecord {
  id: string;
  engagement_id: string;
  hypothesis_id: string | null;
  condition_description: string;
  pattern: string | null;
  evidence_ids: string[];
  evidence_kinds: string[];
  detected_value: string | null;
  status: FlagConditionStatus;
  detected_at: Iso8601 | null;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface EngagementApprovalRecord {
  id: string;
  engagement_id: string;
  task_id: string | null;
  risk: EngineRiskLevel;
  action_summary: string;
  requested_by: string;
  decided_by: string | null;
  decision: ApprovalDecision | null;
  decided_reason: string | null;
  metadata: JsonRecord;
  created_at: Iso8601;
  decided_at: Iso8601 | null;
}

export interface BenchmarkRunRecord {
  id: string;
  benchmark: string;
  engagement_id: string;
  outcome: 'COMPLETED' | 'SOLVED' | 'STOPPED' | 'FAILED';
  metrics: JsonRecord;
  started_at: Iso8601;
  completed_at: Iso8601 | null;
}

// ---------------------------------------------------------------------------
// Part 8 — Production Hardening records (spec Part 8 §11, §15, §44, §59, §75,
// §85, §89, §91-§99).
// ---------------------------------------------------------------------------

export interface AuditChainRecord extends AuditRecord {
  chain_seq: number;
  prev_hash: string | null;
  content_hash: string | null;
}

export interface ApiCredentialRecord {
  id: string;
  user_id: string;
  kind: 'API_KEY' | 'PERSONAL_ACCESS_TOKEN';
  name: string;
  token_hash: string;
  scopes: string[];
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  created_at: Iso8601;
  expires_at: Iso8601;
  last_used_at: Iso8601 | null;
  revoked_at: Iso8601 | null;
}

export interface CredentialGrantRecord {
  id: string;
  engagement_id: string;
  identity_id: string;
  target_id: string;
  secret_reference: string;
  purpose: 'AUTHENTICATION' | 'VERIFICATION' | 'REPRODUCTION';
  status: 'ISSUED' | 'EXPIRED' | 'REVOKED' | 'CONSUMED';
  created_at: Iso8601;
  expires_at: Iso8601;
  revoked_at: Iso8601 | null;
  consumed_at: Iso8601 | null;
}

export interface ScopeVersionRecord {
  id: string;
  engagement_id: string;
  version: number;
  status: 'PROPOSED' | 'ACTIVE' | 'SUPERSEDED';
  scope: JsonRecord;
  diff: JsonRecord;
  created_by: string;
  created_at: Iso8601;
  activated_at: Iso8601 | null;
}

export interface SecurityEventRecord {
  id: string;
  incident_id: string | null;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  actor: 'AGENT' | 'MODEL' | 'WORKER' | 'USER' | 'PLATFORM';
  engagement_id: string | null;
  description: string;
  metadata: JsonRecord;
  created_at: Iso8601;
}

export interface IncidentRecord {
  id: string;
  status: 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  opened_at: Iso8601;
  resolved_at: Iso8601 | null;
  event_count: number;
}

export interface CircuitBreakerRecord {
  id: string;
  subject: 'AGENT' | 'MODEL';
  subject_id: string;
  engagement_id: string | null;
  category: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  violation_count: number;
  threshold: number;
  tripped_at: Iso8601 | null;
  reset_at: Iso8601 | null;
  updated_at: Iso8601;
}

export interface OutboxEventRecord {
  id: string;
  event_type: string;
  engagement_id: string | null;
  aggregate_id: string;
  causation_id: string | null;
  correlation_id: string | null;
  sequence: number;
  payload: JsonRecord;
  status: 'PENDING' | 'DELIVERED' | 'FAILED' | 'ABANDONED';
  attempts: number;
  created_at: Iso8601;
  delivered_at: Iso8601 | null;
}

export interface RetentionPolicyRecord {
  id: string;
  data_class: string;
  retention_days: number;
  hard_delete: boolean;
  created_at: Iso8601;
  updated_at: Iso8601;
}

export interface BackupRecordRecord {
  id: string;
  label: string;
  file_path: string;
  sha256: string;
  size_bytes: number;
  migrations_applied: number;
  restore_verified_at: Iso8601 | null;
  created_at: Iso8601;
}

export interface EmergencyStopRecord {
  status: 'CLEAR' | 'ENGAGED' | 'RELEASING';
  engaged_at: Iso8601 | null;
  released_at: Iso8601 | null;
  engaged_by: string | null;
  reason: string | null;
  cancelled_tasks: number;
  revoked_grants: number;
}
