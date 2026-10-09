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
