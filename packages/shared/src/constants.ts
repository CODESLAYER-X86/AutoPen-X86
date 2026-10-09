/** Domain enums shared across backend, frontend and contracts. */

export const ENGAGEMENT_MODES = ['PENTEST', 'CTF'] as const;
export type EngagementMode = (typeof ENGAGEMENT_MODES)[number];

export const ENGAGEMENT_STATUSES = [
  'DRAFT',
  'READY',
  'RUNNING',
  'PAUSED',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type EngagementStatus = (typeof ENGAGEMENT_STATUSES)[number];

export const TARGET_TYPES = [
  'URL',
  'DOMAIN',
  'HOST',
  'IP',
  'APPLICATION',
  'CTF_INSTANCE',
] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export const ASSET_TYPES = [
  'HOST',
  'DOMAIN',
  'SUBDOMAIN',
  'APPLICATION',
  'API',
  'WEBSOCKET',
  'SOURCE_REPOSITORY',
  'FILE',
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const IDENTITY_TYPES = ['ANONYMOUS', 'USER', 'ADMIN', 'SERVICE'] as const;
export type IdentityType = (typeof IDENTITY_TYPES)[number];

/** Session types for TARGET-side identities (cookies, tokens, ...). */
export const SESSION_TYPES = ['COOKIE', 'JWT', 'API_KEY', 'BASIC', 'OAUTH', 'CUSTOM'] as const;
export type SessionType = (typeof SESSION_TYPES)[number];

export const SESSION_STATUSES = ['ACTIVE', 'EXPIRED', 'REVOKED', 'INVALID'] as const;
export type SessionStatus = (typeof SESSION_STATUSES)[number];

/** Tool capability vocabulary (spec §16). Part 5 adds the knowledge
 *  capability family (spec Part 5 §84): local reads, web search, web fetch
 *  and case memory are separately gated so operators can grant workers
 *  retrieval without live web access. */
export const TOOL_CAPABILITIES = [
  'READ_ONLY',
  'NETWORK',
  'BROWSER',
  'MUTATION',
  'AUTHENTICATED',
  'DESTRUCTIVE',
  'KNOWLEDGE_LOCAL_READ',
  'KNOWLEDGE_WEB_SEARCH',
  'KNOWLEDGE_WEB_FETCH',
  'KNOWLEDGE_CASE_MEMORY',
] as const;
export type ToolCapability = (typeof TOOL_CAPABILITIES)[number];

export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

/** Model roles (spec §19): strategic leader vs tactical workers. */
export const MODEL_ROLES = ['strategic', 'tactical'] as const;
export type ModelRole = (typeof MODEL_ROLES)[number];

/** Internal event vocabulary (spec §14). Kept in shared so the database,
 *  contracts and services layers share one source of truth. */
export const EVENT_TYPES = [
  'ENGAGEMENT_CREATED',
  'ENGAGEMENT_UPDATED',
  'ENGAGEMENT_READY',
  'ENGAGEMENT_STARTED',
  'ENGAGEMENT_PAUSED',
  'ENGAGEMENT_RESUMED',
  'ENGAGEMENT_COMPLETED',
  'ENGAGEMENT_FAILED',
  'ENGAGEMENT_CANCELLED',
  'TARGET_ADDED',
  'TARGET_REJECTED',
  'SCOPE_UPDATED',
  'IDENTITY_CREATED',
  'OBSERVATION_CREATED',
  'HYPOTHESIS_CREATED',
  'HYPOTHESIS_UPDATED',
  'TASK_CREATED',
  'TASK_STARTED',
  'TASK_COMPLETED',
  'TASK_FAILED',
  'HTTP_REQUEST_SENT',
  'HTTP_RESPONSE_RECEIVED',
  'BROWSER_NAVIGATION',
  'BROWSER_ACTION',
  'BROWSER_REQUEST',
  'BROWSER_RESPONSE',
  'EVIDENCE_CREATED',
  'FINDING_CREATED',
  'FINDING_VERIFIED',
  'AGENT_DECISION',
  'AGENT_ERROR',
  'TOOL_INVOKED',
  'TOOL_COMPLETED',
  // Part 2 — Agent Operating System event vocabulary (spec Part 2 §59).
  'AGENT_RUN_CREATED',
  'AGENT_RUN_STARTED',
  'AGENT_RUN_PAUSED',
  'AGENT_RUN_RESUMED',
  'AGENT_RUN_WAITING',
  'AGENT_RUN_COMPLETED',
  'AGENT_RUN_FAILED',
  'AGENT_RUN_CANCELLED',
  'AGENT_CYCLE_COMPLETED',
  'LEADER_DECISION_RECORDED',
  'LEADER_DECISION_REJECTED',
  'TASK_QUEUED',
  'TASK_DISPATCHED',
  'TASK_RETRY',
  'TASK_CANCELLED',
  'TASK_RECOVERY_PENDING',
  'TASK_BLOCKED',
  'WORKER_STARTED',
  'WORKER_COMPLETED',
  'HYPOTHESIS_CONFIRMED',
  'HYPOTHESIS_DISPROVED',
  'HYPOTHESIS_ABANDONED',
  'TEST_RECORDED',
  'TEST_DUPLICATE',
  'DEAD_END_RECORDED',
  'STRATEGY_CHANGED',
  'VERIFICATION_REQUESTED',
  'FINDING_REJECTED',
  'QUOTA_DELAY',
  'QUOTA_EXHAUSTED',
  'OSCILLATION_DETECTED',
  'LOOP_PROTECTION_TRIGGERED',
  'HUMAN_OVERRIDE',
  // Part 3 — Interaction layer event vocabulary (spec Part 3 §11, §58).
  'HTTP_REQUEST_RECORDED',
  'HTTP_RESPONSE_RECORDED',
  'HTTP_MUTATION_APPLIED',
  'HTTP_REPLAY_EXECUTED',
  'HAR_IMPORTED',
  'BROWSER_SESSION_STARTED',
  'BROWSER_SESSION_CLOSED',
  'BROWSER_CONTEXT_CREATED',
  'BROWSER_CONTEXT_CLOSED',
  'BROWSER_EVENT_RECORDED',
  'DOM_SNAPSHOT_CAPTURED',
  'DOM_CHANGE_DETECTED',
  'DOWNLOAD_CAPTURED',
  'WEBSOCKET_CONNECTION_OBSERVED',
  'WEBSOCKET_MESSAGE_OBSERVED',
  'SESSION_EXPIRATION_DETECTED',
  'AUTH_WORKFLOW_RECORDED',
  'TOOL_EXECUTION_RECORDED',
  'RATE_LIMIT_ENFORCED',
  // Part 4 — Security Reasoning Engine event vocabulary (spec Part 4 §109).
  'ENDPOINT_DISCOVERED',
  'ENDPOINT_MERGED',
  'PARAMETER_OBSERVED',
  'AUTHORIZATION_MATRIX_UPDATED',
  'WORKFLOW_RECONSTRUCTED',
  'WORKFLOW_TRANSITION_RECORDED',
  'DATA_FLOW_RECORDED',
  'SECURITY_SIGNAL_GENERATED',
  'OBJECT_CANDIDATE_CREATED',
  'ATTACK_GRAPH_UPDATED',
  'DIFFERENTIAL_COMPARISON_RECORDED',
  'VERIFICATION_CREATED',
  'VERIFICATION_COMPLETED',
  'REASONING_HYPOTHESES_APPLIED',
  'REASONING_PROCESSOR_FAILED',
  'REASONING_INGEST_COMPLETED',
  // Part 5 — Knowledge & Web Research event vocabulary (spec Part 5 §86,
  // §119). Every retrieval/research action is observable and auditable.
  'KNOWLEDGE_QUERY',
  'KNOWLEDGE_RESULT',
  'WEB_RESEARCH_STARTED',
  'WEB_SOURCE_SELECTED',
  'WEB_DOCUMENT_FETCHED',
  'KNOWLEDGE_PACKET_CREATED',
  'KNOWLEDGE_SOURCE_SYNCED',
  'KNOWLEDGE_DOCUMENT_INDEXED',
  'KNOWLEDGE_INGESTION_FAILED',
  'RESEARCH_COMPLETED',
  // Part 6 — Autonomous Pentest & CTF Engine event vocabulary (spec Part 6
  // §8, §6, §25-§26, §31, §41-§42, §48-§50, §55, §87). Every meaningful
  // engine transition is observable; the chain decision -> task -> worker ->
  // tool -> observation -> hypothesis -> evidence -> verification -> finding
  // stays connected through correlation ids.
  'AUTONOMOUS_ENGINE_STARTED',
  'AUTONOMOUS_PHASE_CHANGED',
  'AUTONOMOUS_ENGINE_PAUSED',
  'AUTONOMOUS_ENGINE_RESUMED',
  'AUTONOMOUS_ENGINE_STOPPED',
  'AUTONOMOUS_RECOVERY_COMPLETED',
  'RECON_PIPELINE_STARTED',
  'RECON_TASK_PLANNED',
  'RECON_PIPELINE_COMPLETED',
  'HYPOTHESIS_CANDIDATES_CONSUMED',
  'TEST_CANDIDATES_COMPILED',
  'REASONING_BRANCH_CREATED',
  'REASONING_BRANCH_UPDATED',
  'REASONING_BRANCH_PRUNED',
  'DIFFERENTIAL_AUTO_REQUESTED',
  'VERIFICATION_BRIDGE_APPLIED',
  'FINDING_CONFIDENCE_COMPUTED',
  'STOP_CONDITION_MET',
  'BUDGET_THRESHOLD_EXCEEDED',
  'TASK_LEASE_EXPIRED',
  'APPROVAL_REQUESTED',
  'APPROVAL_DECIDED',
  'CTF_CONTEXT_CREATED',
  'CTF_CLUE_ANALYZED',
  'CTF_INTERPRETATION_RECORDED',
  'FLAG_CONDITION_HYPOTHESIZED',
  'FLAG_DETECTED',
  'CHALLENGE_SOLVED',
  'COVERAGE_UPDATED',
  'REPLAN_REQUESTED',
  'BENCHMARK_RUN_COMPLETED',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

// ---------------------------------------------------------------------------
// Part 2 — Agent Operating System domain enums (spec Part 2 §2-§3, §9, §11,
// §18, §22-23, §27, §47, §55, §59).
// ---------------------------------------------------------------------------

/** AgentRun lifecycle (Part 2 §3). */
export const AGENT_RUN_STATUSES = [
  'CREATED',
  'INITIALIZING',
  'RUNNING',
  'PAUSED',
  'WAITING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type AgentRunStatus = (typeof AGENT_RUN_STATUSES)[number];

/** Task lifecycle (Part 2 §18) + RECOVERY_PENDING (Part 2 §64). */
export const TASK_STATUSES = [
  'CREATED',
  'QUEUED',
  'READY',
  'RUNNING',
  'WAITING',
  'COMPLETED',
  'PARTIAL',
  'FAILED',
  'CANCELLED',
  'EXPIRED',
  'RECOVERY_PENDING',
] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

/** Logical worker specialisations (Part 2 §11) — one shared runtime. */
export const WORKER_TYPES = [
  'HTTP_WORKER',
  'BROWSER_WORKER',
  'SOURCE_WORKER',
  'ANALYSIS_WORKER',
] as const;
export type WorkerType = (typeof WORKER_TYPES)[number];

/**
 * Strategic decision vocabulary (Part 2 §9). Exactly these nine — anything
 * else in model output is rejected by schema validation.
 */
export const DECISION_TYPES = [
  'CREATE_TASK',
  'CREATE_PARALLEL_TASKS',
  'UPDATE_HYPOTHESIS',
  'REQUEST_KNOWLEDGE',
  'REQUEST_RECON',
  'REQUEST_VERIFICATION',
  'WAIT',
  'STOP',
  'PAUSE',
] as const;
export type DecisionType = (typeof DECISION_TYPES)[number];

/**
 * Investigation task types (Part 2 §4/§13). Security methodology is a source
 * of candidate tests, not a mandatory sequence (Part 2 §5) — this list is an
 * open vocabulary, not a checklist algorithm.
 */
export const TASK_TYPES = [
  'RECON',
  'HTTP_ANALYSIS',
  'BROWSER_INVESTIGATION',
  'SOURCE_ANALYSIS',
  'AUTHORIZATION_ANALYSIS',
  'AUTHENTICATION_ANALYSIS',
  'SESSION_ANALYSIS',
  'INPUT_VALIDATION_ANALYSIS',
  'CTF_CLUE_ANALYSIS',
  'VERIFICATION',
  'KNOWLEDGE_SUMMARY',
  'GENERAL_ANALYSIS',
] as const;
export type TaskType = (typeof TASK_TYPES)[number];

/** Worker result statuses (Part 2 §17). */
export const WORKER_RESULT_STATUSES = [
  'COMPLETED',
  'PARTIAL',
  'BLOCKED',
  'FAILED',
  'NEEDS_CONTEXT',
  'NEEDS_TOOL',
  'NEEDS_IDENTITY',
] as const;
export type WorkerResultStatus = (typeof WORKER_RESULT_STATUSES)[number];

/** Hypothesis lifecycle (Part 2 §22). */
export const HYPOTHESIS_STATUSES = [
  'PROPOSED',
  'ACTIVE',
  'TESTING',
  'SUPPORTED',
  'CONFIRMED',
  'DISPROVED',
  'ABANDONED',
] as const;
export type HypothesisStatus = (typeof HYPOTHESIS_STATUSES)[number];

/** Hypothesis taxonomy (Part 2 §23) — UNKNOWN is a first-class citizen (CTF). */
export const HYPOTHESIS_TYPES = [
  'AUTHENTICATION',
  'AUTHORIZATION',
  'INPUT_VALIDATION',
  'INJECTION',
  'CLIENT_SIDE',
  'SERVER_SIDE',
  'SESSION',
  'BUSINESS_LOGIC',
  'CONFIGURATION',
  'DATA_EXPOSURE',
  'CRYPTOGRAPHIC',
  'RACE_CONDITION',
  'CTF_CLUE',
  'UNKNOWN',
] as const;
export type HypothesisType = (typeof HYPOTHESIS_TYPES)[number];

/** Hypothesis confidence changes produced by workers (Part 2 §16). */
export const HYPOTHESIS_CHANGES = [
  'INCREASE_CONFIDENCE',
  'DECREASE_CONFIDENCE',
  'SUPPORT',
  'CONTRADICT',
  'CONFIRM',
  'DISPROVE',
  'ABANDON',
] as const;
export type HypothesisChange = (typeof HYPOTHESIS_CHANGES)[number];

/** Test registry statuses (Part 2 §28). */
export const TEST_STATUSES = [
  'PENDING',
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'DUPLICATE',
] as const;
export type TestStatus = (typeof TEST_STATUSES)[number];

/** Finding promotion ladder (Part 2 §55): hypothesis != finding. */
// FINDING_STATUSES / FindingStatus are declared with the Part 6 extension in
// the Part 6 section below (PROPOSED/CONFIRMED/REJECTED + CANDIDATE/VERIFIED).

/** Separate token budgets (Part 2 §38). */
export const TOKEN_PURPOSES = [
  'leader',
  'worker',
  'knowledge',
  'summarization',
  'verification',
] as const;
export type TokenPurpose = (typeof TOKEN_PURPOSES)[number];

/** AgentPolicy outcomes (Part 2 §67). */
export const POLICY_OUTCOMES = ['ALLOW', 'DENY', 'REQUIRE_USER_APPROVAL'] as const;
export type PolicyOutcome = (typeof POLICY_OUTCOMES)[number];

// ---------------------------------------------------------------------------
// Part 3 — Interaction layer domain enums (spec Part 3 §5, §7-§9, §11, §16,
// §17, §20, §25, §29, §36, §40, §43, §46, §57, §67, §70-§72).
// ---------------------------------------------------------------------------

/** HTTP methods the engine accepts (Part 3 §15). */
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Request body types (Part 3 §67). */
export const HTTP_BODY_TYPES = [
  'JSON',
  'FORM_URLENCODED',
  'MULTIPART',
  'TEXT',
  'XML',
  'BINARY',
  'EMPTY',
] as const;
export type HttpBodyType = (typeof HTTP_BODY_TYPES)[number];

/** Response content classes (Part 3 §17). */
export const HTTP_CONTENT_TYPES = [
  'JSON',
  'HTML',
  'XML',
  'TEXT',
  'BINARY',
  'IMAGE',
  'FILE',
  'UNKNOWN',
] as const;
export const HTTP_CONTENT_KIND_LABELS = HTTP_CONTENT_TYPES;
export type HttpContentKind = (typeof HTTP_CONTENT_TYPES)[number];

/** Where a recorded request came from (Part 3 §16). */
export const HTTP_REQUEST_SOURCES = ['BROWSER', 'HTTP_WORKER', 'IMPORTED', 'REPLAY'] as const;
export type HttpRequestSource = (typeof HTTP_REQUEST_SOURCES)[number];

/** Request provenance: why the request happened (Part 3 §55). */
export const HTTP_PROVENANCE_SOURCES = [
  'browser_observation',
  'leader_task',
  'worker_task',
  'replay',
  'verification',
  'import',
] as const;
export type HttpProvenanceSource = (typeof HTTP_PROVENANCE_SOURCES)[number];

/** Traffic sources (Part 3 §40). */
export const TRAFFIC_SOURCES = ['BROWSER_NATIVE', 'EXPLICIT_PROXY', 'IMPORTED_TRAFFIC'] as const;
export type TrafficSource = (typeof TRAFFIC_SOURCES)[number];

/** Browser context lifecycle (Part 3 §5). */
export const BROWSER_CONTEXT_STATUSES = [
  'CREATE',
  'INITIALIZE',
  'READY',
  'ACTIVE',
  'PAUSED',
  'EXPIRED',
  'CLOSING',
  'CLOSED',
  'FAILED',
] as const;
export type BrowserContextStatus = (typeof BROWSER_CONTEXT_STATUSES)[number];

/** Deterministic browser actions (Part 3 §7). */
export const BROWSER_ACTIONS = [
  'navigate',
  'go_back',
  'go_forward',
  'reload',
  'click',
  'fill',
  'select_option',
  'check',
  'uncheck',
  'press',
  'hover',
  'wait_for_url',
  'wait_for_selector',
  'screenshot',
  'snapshot',
] as const;
export type BrowserAction = (typeof BROWSER_ACTIONS)[number];

/** Selector strategies (Part 3 §9). Stable semantic selectors first. */
export const SELECTOR_STRATEGIES = [
  'role',
  'text',
  'label',
  'placeholder',
  'css',
  'xpath',
  'test_id',
] as const;
export type SelectorStrategy = (typeof SELECTOR_STRATEGIES)[number];

/** Structured browser event stream (Part 3 §11). */
export const BROWSER_EVENT_TYPES = [
  'PAGE_CREATED',
  'PAGE_CLOSED',
  'NAVIGATION_STARTED',
  'NAVIGATION_COMPLETED',
  'NAVIGATION_FAILED',
  'CLICK',
  'INPUT',
  'FORM_SUBMIT',
  'DOM_CHANGE',
  'REQUEST_STARTED',
  'REQUEST_FINISHED',
  'REQUEST_FAILED',
  'RESPONSE_RECEIVED',
  'CONSOLE_MESSAGE',
  'PAGE_ERROR',
  'COOKIE_CHANGED',
  'STORAGE_CHANGED',
  'DOWNLOAD_STARTED',
  'DOWNLOAD_COMPLETED',
  'WEBSOCKET_CREATED',
  'WEBSOCKET_MESSAGE',
  'WEBSOCKET_CLOSED',
] as const;
export type BrowserEventType = (typeof BROWSER_EVENT_TYPES)[number];

/** Mutation locations (Part 3 §20-§21). */
export const HTTP_MUTATION_LOCATIONS = [
  'query',
  'path',
  'header',
  'cookie',
  'body_json',
  'body_form',
  'method',
] as const;
export type HttpMutationLocation = (typeof HTTP_MUTATION_LOCATIONS)[number];

/** Mutation operations (Part 3 §70-§71). */
export const HTTP_MUTATION_OPERATIONS = [
  'add',
  'remove',
  'replace',
  'duplicate',
  'reorder',
] as const;
export type HttpMutationOperation = (typeof HTTP_MUTATION_OPERATIONS)[number];

/** Authentication state kinds the session manager supports (Part 3 §25). */
export const AUTH_STATE_KINDS = [
  'COOKIE',
  'BEARER',
  'JWT',
  'API_KEY',
  'CUSTOM_HEADER',
  'BROWSER_STORAGE',
] as const;
export type AuthStateKind = (typeof AUTH_STATE_KINDS)[number];

/** WebSocket message directions (Part 3 §36). */
export const WS_MESSAGE_DIRECTIONS = ['CLIENT_TO_SERVER', 'SERVER_TO_CLIENT'] as const;
export type WsMessageDirection = (typeof WS_MESSAGE_DIRECTIONS)[number];

/** Evidence classification (Part 3 §57). */
export const EVIDENCE_CLASSIFICATIONS = [
  'RAW',
  'DERIVED',
  'SUMMARY',
  'SCREENSHOT',
  'NETWORK',
  'BROWSER_TRACE',
  'SOURCE',
] as const;
export type EvidenceClassification = (typeof EVIDENCE_CLASSIFICATIONS)[number];

/** Session expiration signals (Part 3 §27). */
export const SESSION_EXPIRATION_SIGNALS = [
  'HTTP_401',
  'HTTP_403',
  'AUTH_REDIRECT',
  'TOKEN_INVALID',
  'LOGOUT_DETECTED',
  'SESSION_RESET',
] as const;
export type SessionExpirationSignal = (typeof SESSION_EXPIRATION_SIGNALS)[number];

export const PLATFORM_VERSION = '0.6.0-part6';
export const PLATFORM_NAME = 'Aegis Platform';

// ---------------------------------------------------------------------------
// Part 4 — Security Reasoning Engine domain enums (spec Part 4 §3, §7-§13,
// §10, §14-§17, §23, §25, §30, §35, §42, §51, §70, §77-78, §84, §98, §102,
// §131).
// ---------------------------------------------------------------------------

/** Endpoint lifecycle (Part 4 §10). */
export const ENDPOINT_STATUSES = [
  'DISCOVERED',
  'OBSERVED',
  'MAPPED',
  'TESTING',
  'INTERESTING',
  'VERIFIED',
  'IGNORED',
] as const;
export type EndpointStatus = (typeof ENDPOINT_STATUSES)[number];

/** How an asset was discovered (Part 4 §12). Inferred sources are never
 *  represented as observations (§12: never fake an observed endpoint). */
export const DISCOVERY_SOURCES = [
  'BROWSER_NAVIGATION',
  'BROWSER_NETWORK',
  'HTML',
  'FORM',
  'JAVASCRIPT',
  'WEBSOCKET',
  'ROBOTS_TXT',
  'SITEMAP',
  'API_SPECIFICATION',
  'IMPORTED_TRAFFIC',
  'USER_INPUT',
  'KNOWLEDGE_INFERENCE',
] as const;
export type DiscoverySource = (typeof DISCOVERY_SOURCES)[number];

/** Confidence categories for discovered assets (Part 4 §13). */
export const CONFIDENCE_CATEGORIES = [
  'OBSERVED',
  'STRONGLY_INFERRED',
  'INFERRED',
  'UNVERIFIED',
] as const;
export type ConfidenceCategory = (typeof CONFIDENCE_CATEGORIES)[number];

/** Parameter locations (Part 4 §14). */
export const PARAMETER_LOCATIONS = [
  'QUERY',
  'PATH',
  'JSON',
  'FORM',
  'MULTIPART',
  'HEADER',
  'COOKIE',
  'WEBSOCKET',
  'GRAPHQL',
  'HTML_FORM',
  'JAVASCRIPT',
] as const;
export type ParameterLocation = (typeof PARAMETER_LOCATIONS)[number];

/** Deterministic value characteristics (Part 4 §17). */
export const VALUE_CHARACTERISTICS = [
  'NUMERIC',
  'UUID',
  'EMAIL',
  'URL',
  'JWT_LIKE',
  'BASE64_LIKE',
  'HEXADECIMAL',
  'TIMESTAMP',
  'JSON',
  'OPAQUE_TOKEN',
  'FILE',
  'IDENTIFIER',
] as const;
export type ValueCharacteristic = (typeof VALUE_CHARACTERISTICS)[number];

/** Parameter semantic classification candidates (Part 4 §16). */
export const PARAMETER_SEMANTICS = [
  'IDENTIFIER',
  'PRIVILEGE',
  'URL',
  'AUTHENTICATION',
  'MONETARY',
  'NUMERIC',
  'UPLOAD',
  'TEXT',
  'UNKNOWN',
] as const;
export type ParameterSemantic = (typeof PARAMETER_SEMANTICS)[number];

/** Authorization matrix outcomes (Part 4 §23). 403 is not equated with every
 *  possible denial — each outcome class is recorded explicitly. */
export const ACCESS_OUTCOMES = [
  'ALLOWED',
  'DENIED',
  'REDIRECTED',
  'UNKNOWN',
  'ERROR',
] as const;
export type AccessOutcome = (typeof ACCESS_OUTCOMES)[number];

/** Deterministic security signal types (Part 4 §42, §121). Signals are NOT
 *  findings (§136: OBSERVATION != VULNERABILITY). */
export const SIGNAL_TYPES = [
  'AUTH_STATE_CHANGE',
  'OBJECT_IDENTIFIER',
  'CROSS_IDENTITY_DIFFERENCE',
  'CROSS_IDENTITY_OBJECT_REFERENCE',
  'REFLECTED_INPUT',
  'UNEXPECTED_REDIRECT',
  'STATE_TRANSITION_ANOMALY',
  'SENSITIVE_DATA_EXPOSURE',
  'ERROR_DISCLOSURE',
  'UNUSUAL_RESPONSE_DIFFERENCE',
  'CLIENT_CONTROLLED_VALUE',
  'TOKEN_PATTERN',
  'UNEXPECTED_METHOD_BEHAVIOR',
] as const;
export type SignalType = (typeof SIGNAL_TYPES)[number];

/** Signal lifecycle: NEW (generated), CONSUMED (drove a hypothesis),
 *  SUPERSEDED (a newer, more specific signal replaces it). */
export const SIGNAL_STATUSES = ['NEW', 'CONSUMED', 'SUPERSEDED'] as const;
export type SignalStatus = (typeof SIGNAL_STATUSES)[number];

/** Workflow candidate lifecycle (Part 4 §34). */
export const WORKFLOW_STATUSES = ['CANDIDATE', 'CONFIRMED', 'REJECTED'] as const;
export type WorkflowStatus = (typeof WORKFLOW_STATUSES)[number];

/** Transition observation kind (Part 4 §35). Inferred never becomes fact. */
export const TRANSITION_OBSERVATION_KINDS = ['OBSERVED', 'INFERRED'] as const;
export type TransitionObservationKind = (typeof TRANSITION_OBSERVATION_KINDS)[number];

/** Mutation strategy categories (Part 4 §51). The LLM chooses a category;
 *  the deterministic engine generates the actual mutation. */
export const MUTATION_CATEGORIES = [
  'IDENTIFIER',
  'TYPE',
  'BOUNDARY',
  'STRUCTURE',
  'METHOD',
  'STATE',
  'AUTHENTICATION',
  'AUTHORIZATION',
  'HEADER',
  'COOKIE',
  'JSON',
  'FORM',
  'PATH',
  'QUERY',
] as const;
export type MutationCategory = (typeof MUTATION_CATEGORIES)[number];

/** Verification lifecycle (Part 4 §72). The verifier is skeptical by design. */
export const VERIFICATION_STATUSES = [
  'PENDING',
  'RUNNING',
  'VERIFIED',
  'REFUTED',
  'INCONCLUSIVE',
] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

/** Per-check outcome inside a verification checklist (Part 4 §72). */
export const VERIFICATION_CHECK_STATUSES = [
  'PASS',
  'FAIL',
  'UNKNOWN',
  'NOT_APPLICABLE',
] as const;
export type VerificationCheckStatus = (typeof VERIFICATION_CHECK_STATUSES)[number];

/** Evidence strength classification (Part 4 §70). Explainable, not numeric. */
export const EVIDENCE_STRENGTH_LEVELS = [
  'WEAK',
  'MODERATE',
  'STRONG',
  'CONFIRMATORY',
  'CONTRADICTORY',
] as const;
export type EvidenceStrengthLevel = (typeof EVIDENCE_STRENGTH_LEVELS)[number];

/** Test result classification (Part 4 §102). INCONCLUSIVE is a valid result. */
export const TEST_OUTCOMES = [
  'NO_SIGNAL',
  'INTERESTING',
  'SUPPORTS_HYPOTHESIS',
  'CONTRADICTS_HYPOTHESIS',
  'INCONCLUSIVE',
  'ERROR',
  'BLOCKED',
] as const;
export type TestOutcome = (typeof TEST_OUTCOMES)[number];

/** Attack-surface graph node types (Part 4 §4). */
export const ATTACK_NODE_TYPES = [
  'ENGAGEMENT',
  'TARGET',
  'HOST',
  'PORT',
  'APPLICATION',
  'PAGE',
  'ENDPOINT',
  'PARAMETER',
  'FORM',
  'SCRIPT',
  'API',
  'WEBSOCKET',
  'IDENTITY',
  'SESSION',
  'OBJECT',
  'WORKFLOW',
  'STATE',
  'SOURCE_FILE',
  'ARTIFACT',
  'HYPOTHESIS',
  'FINDING',
] as const;
export type AttackNodeType = (typeof ATTACK_NODE_TYPES)[number];

/** Attack-surface graph edge relations (Part 4 §4). */
export const ATTACK_EDGE_RELATIONS = [
  'contains',
  'loads',
  'calls',
  'accepts',
  'owns',
  'accesses',
  'belongs_to',
  'transitions_to',
  'concerns',
  'supports',
  'references',
  'observes',
  'establishes',
] as const;
export type AttackEdgeRelation = (typeof ATTACK_EDGE_RELATIONS)[number];

/** Data-flow source kinds (Part 4 §38). */
export const DATA_FLOW_SOURCE_KINDS = [
  'FORM_FIELD',
  'URL_PARAM',
  'JSON_FIELD',
  'HEADER',
  'COOKIE',
  'STORAGE',
  'WEBSOCKET_MESSAGE',
  'UPLOADED_FILE',
  'BROWSER_STATE',
] as const;
export type DataFlowSourceKind = (typeof DATA_FLOW_SOURCE_KINDS)[number];

/** Data-flow sink kinds (Part 4 §40). */
export const DATA_FLOW_SINK_KINDS = [
  'HTTP_RESPONSE',
  'HTML_DOM',
  'SCRIPT_CONTEXT',
  'REDIRECT',
  'DOWNLOAD',
  'WEBSOCKET',
  'APPLICATION_STATE',
  'REQUEST_PARAMETER',
] as const;
export type DataFlowSinkKind = (typeof DATA_FLOW_SINK_KINDS)[number];

/** Deterministic data transformations (Part 4 §39). */
export const DATA_TRANSFORMATIONS = [
  'URL_ENCODED',
  'JSON_SERIALIZED',
  'BASE64',
  'HEX',
  'COMPRESSED',
  'JWT_ENCODED',
  'MULTIPART_ENCODED',
] as const;
export type DataTransformation = (typeof DATA_TRANSFORMATIONS)[number];

/** Correlation kinds that produce data-flow relationships (Part 4 §91-§92). */
export const CORRELATION_KINDS = [
  'FORM_TO_REQUEST',
  'SCRIPT_TO_ENDPOINT',
  'STORAGE_TO_REQUEST',
  'INPUT_TO_OUTPUT',
  'WS_REQUEST_RESPONSE',
] as const;
export type CorrelationKind = (typeof CORRELATION_KINDS)[number];

/** Reasoning-engine stop recommendations (Part 4 §131). Part 2 decides. */
export const STOP_RECOMMENDATIONS = [
  'NO_ACTIONABLE_HYPOTHESES',
  'SUFFICIENT_EVIDENCE',
  'REQUIRES_USER_INPUT',
  'REQUIRES_IDENTITY',
  'REQUIRES_BROWSER_STATE',
  'OUT_OF_SCOPE',
  'RESOURCE_LIMIT',
] as const;
export type StopRecommendation = (typeof STOP_RECOMMENDATIONS)[number];

// ---------------------------------------------------------------------------
// Part 5 — Security Knowledge & Web Research System domain enums (spec Part 5
// §3, §5-§6, §8-§9, §29, §43, §58, §92, §102-§103).
// ---------------------------------------------------------------------------

/** Knowledge source categories (Part 5 §3). */
export const KNOWLEDGE_SOURCE_TYPES = [
  'OFFICIAL_SECURITY',
  'SECURITY_TRAINING',
  'STANDARDS',
  'TECHNICAL_DOCUMENTATION',
  'SECURITY_RESEARCH',
  'CTF_WRITEUPS',
  'CHALLENGE_REPOSITORIES',
  'CASE_MEMORY',
  'LIVE_WEB',
] as const;
export type KnowledgeSourceType = (typeof KNOWLEDGE_SOURCE_TYPES)[number];

/** Trust categories (Part 5 §6). A ranking factor — NEVER a policy override. */
export const KNOWLEDGE_TRUST_LEVELS = [
  'OFFICIAL',
  'TRUSTED_TRAINING',
  'RESEARCH',
  'CTF',
  'COMMUNITY',
  'UNTRUSTED',
] as const;
export type KnowledgeTrustLevel = (typeof KNOWLEDGE_TRUST_LEVELS)[number];

/** Supported knowledge document formats (Part 5 §54). Adapters allow more. */
export const KNOWLEDGE_DOCUMENT_TYPES = [
  'HTML',
  'MARKDOWN',
  'TXT',
  'JSON',
  'XML',
  'PDF',
] as const;
export type KnowledgeDocumentType = (typeof KNOWLEDGE_DOCUMENT_TYPES)[number];

/** Source refresh strategies (Part 5 §29/§92). */
export const KNOWLEDGE_UPDATE_STRATEGIES = [
  'MANUAL',
  'SCHEDULED',
  'ON_DEMAND',
  'INCREMENTAL',
] as const;
export type KnowledgeUpdateStrategy = (typeof KNOWLEDGE_UPDATE_STRATEGIES)[number];

/** Ingestion pipeline lifecycle (Part 5 §115-§116). Embedding failure keeps
 *  the document keyword-searchable; parser failure retains the raw artifact. */
export const KNOWLEDGE_INGESTION_STATUSES = [
  'PENDING',
  'FETCHED',
  'PARSED',
  'INDEXED',
  'EMBEDDING_FAILED',
  'FAILED',
] as const;
export type KnowledgeIngestionStatus = (typeof KNOWLEDGE_INGESTION_STATUSES)[number];

/** Semantic chunk kinds (Part 5 §9-§10, §56). Code blocks are stored
 *  separately so retrieval can target conceptual examples without
 *  contaminating surrounding prose. */
export const KNOWLEDGE_CHUNK_KINDS = ['TEXT', 'HEADING', 'CODE', 'TABLE', 'PROCEDURE', 'EXAMPLE'] as const;
export type KnowledgeChunkKind = (typeof KNOWLEDGE_CHUNK_KINDS)[number];

/** Shared security taxonomy (Part 5 §58). Aligns with Part 4 hypothesis
 *  categories so knowledge and reasoning share one vocabulary. */
export const SECURITY_TAXONOMY = [
  'AUTHENTICATION',
  'AUTHORIZATION',
  'SESSION',
  'INPUT_VALIDATION',
  'INJECTION',
  'XSS',
  'CSRF',
  'SSRF',
  'FILE_HANDLING',
  'API',
  'GRAPHQL',
  'WEBSOCKET',
  'BUSINESS_LOGIC',
  'RACE_CONDITION',
  'CRYPTO',
  'CONFIGURATION',
  'INFORMATION_DISCLOSURE',
  'CLIENT_SIDE',
] as const;
export type SecurityTaxonomyCategory = (typeof SECURITY_TAXONOMY)[number];

/** Research modes (Part 5 §103). The engagement chooses the mode; default
 *  is CURATED_WEB — unrestricted research is never default (§104). */
export const RESEARCH_MODES = [
  'LOCAL_ONLY',
  'CURATED_WEB',
  'OPEN_RESEARCH',
  'CTF_RESEARCH',
] as const;
export type ResearchMode = (typeof RESEARCH_MODES)[number];

/** Research task lifecycle (Part 5 §71). */
export const RESEARCH_STATUSES = [
  'PENDING',
  'RUNNING',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
] as const;
export type ResearchStatus = (typeof RESEARCH_STATUSES)[number];

/** CTF retrieval modes (Part 5 §102). Pattern retrieval expands the search
 *  space; exact-case retrieval is for benchmark evaluation only. */
export const CTF_RETRIEVAL_MODES = ['PATTERN_RETRIEVAL', 'EXACT_CASE_RETRIEVAL'] as const;
export type CtfRetrievalMode = (typeof CTF_RETRIEVAL_MODES)[number];

/** Reference identifier kinds extracted from documents (Part 5 §57/§76). */
export const KNOWLEDGE_REFERENCE_KINDS = ['CVE', 'CWE', 'OWASP', 'RFC', 'OTHER'] as const;
export type KnowledgeReferenceKind = (typeof KNOWLEDGE_REFERENCE_KINDS)[number];

// ---------------------------------------------------------------------------
// Part 6 — Autonomous Pentest & CTF Engine domain enums (spec Part 6 §2, §6,
// §15, §21, §29-§31, §33, §39, §49-§51, §55, §59-§60, §65, §77, §79).
// ---------------------------------------------------------------------------

/**
 * Autonomous engine phases (Part 6 §6). The engine-level state machine sits
 * ABOVE the Part 2 agent-run state machine: phases describe WHAT the engine
 * is doing strategically, agent runs describe HOW tasks execute. Phases are
 * persisted in `autonomous_engine_states` (never process memory).
 *
 * Terminal: COMPLETED, STOPPED, CANCELLED, FAILED.
 * Waiting: WAITING_FOR_USER / RESOURCE / IDENTITY / QUOTA.
 */
export const AUTONOMOUS_PHASES = [
  'CREATED',
  'INITIALIZING',
  'RECON',
  'MODELING',
  'HYPOTHESIS_GENERATION',
  'TESTING',
  'ANALYSIS',
  'VERIFICATION',
  'REPLANNING',
  'COMPLETED',
  'STOPPED',
  'CANCELLED',
  'FAILED',
  'WAITING_FOR_USER',
  'WAITING_FOR_RESOURCE',
  'WAITING_FOR_IDENTITY',
  'WAITING_FOR_QUOTA',
] as const;
export type AutonomousPhase = (typeof AUTONOMOUS_PHASES)[number];

/** Phases from which the engine may continue autonomously. */
export const AUTONOMOUS_RUNNABLE_PHASES: readonly AutonomousPhase[] = [
  'CREATED',
  'INITIALIZING',
  'RECON',
  'MODELING',
  'HYPOTHESIS_GENERATION',
  'TESTING',
  'ANALYSIS',
  'VERIFICATION',
  'REPLANNING',
  'WAITING_FOR_USER',
  'WAITING_FOR_RESOURCE',
  'WAITING_FOR_IDENTITY',
  'WAITING_FOR_QUOTA',
];

/** Terminal engine phases (§6). */
export const AUTONOMOUS_TERMINAL_PHASES: readonly AutonomousPhase[] = [
  'COMPLETED',
  'STOPPED',
  'CANCELLED',
  'FAILED',
];

/**
 * Reasoning branch lifecycle (Part 6 §65). Branches group hypotheses that
 * share an interpretation; pruned branches are PRESERVED (never deleted).
 */
export const BRANCH_STATUSES = ['ACTIVE', 'PAUSED', 'PRUNED', 'DISPROVED', 'COMPLETED'] as const;
export type BranchStatus = (typeof BRANCH_STATUSES)[number];

/** Dead-end memory scope (Part 6 §39). */
export const DEAD_END_SCOPES = ['ENGAGEMENT', 'APPLICATION', 'ENDPOINT', 'GLOBAL'] as const;
export type DeadEndScope = (typeof DEAD_END_SCOPES)[number];

/** Reconnaissance depth levels (Part 6 §77). */
export const RECON_LEVELS = [0, 1, 2, 3, 4] as const;
export type ReconLevel = (typeof RECON_LEVELS)[number];

/** CTF challenge lifecycle (Part 6 §31). Separate from severity. */
export const CTF_STATUSES = ['UNSOLVED', 'PARTIAL', 'SOLVED'] as const;
export type CtfStatus = (typeof CTF_STATUSES)[number];

/** Where a CTF clue came from (Part 6 §29). */
export const CTF_CLUE_SOURCES = ['TITLE', 'DESCRIPTION', 'HINT', 'ARTIFACT', 'OBSERVATION', 'USER'] as const;
export type CtfClueSource = (typeof CTF_CLUE_SOURCES)[number];

/** CTF clue lifecycle. */
export const CTF_CLUE_STATUSES = ['NEW', 'ANALYZED', 'INTERPRETED', 'CONSUMED', 'DEAD_END'] as const;
export type CtfClueStatus = (typeof CTF_CLUE_STATUSES)[number];

/** Flag-condition lifecycle (Part 6 §31): hypothesized -> detected -> solved. */
export const FLAG_CONDITION_STATUSES = [
  'HYPOTHESIZED',
  'SUPPORTED',
  'DETECTED',
  'REFUTED',
] as const;
export type FlagConditionStatus = (typeof FLAG_CONDITION_STATUSES)[number];

/** Flag-condition evidence kinds (Part 6 §31). */
export const FLAG_EVIDENCE_KINDS = [
  'FLAG_PATTERN_OBSERVED',
  'SUCCESS_RESPONSE',
  'EXPLICIT_SUCCESS_STATE',
  'VALIDATED_FLAG_ARTIFACT',
  'SERVER_CONFIRMED_COMPLETION',
] as const;
export type FlagEvidenceKind = (typeof FLAG_EVIDENCE_KINDS)[number];

/** Experimental test verdicts (Part 6 §60). The test registry's experimental
 * memory: SUPPORTED advances a hypothesis, DISPROVED records a dead end. */
export const TEST_RESULT_OUTCOMES = [
  'SUPPORTED',
  'DISPROVED',
  'INCONCLUSIVE',
  'BLOCKED',
  'FAILED',
] as const;
export type TestResultOutcome = (typeof TEST_RESULT_OUTCOMES)[number];

/** Human approval decisions for high-risk actions (Part 6 §48-§49). */
export const APPROVAL_DECISIONS = ['APPROVED', 'REJECTED'] as const;
export type ApprovalDecision = (typeof APPROVAL_DECISIONS)[number];

/** Stop condition reasons (Part 6 §50). */
export const STOP_REASONS = [
  'OBJECTIVE_COMPLETED',
  'NO_USEFUL_HYPOTHESES',
  'BUDGET_EXHAUSTED',
  'SCOPE_VIOLATION_RISK',
  'REPEATED_FAILURE',
  'DIMINISHING_RETURNS',
  'USER_STOP',
] as const;
export type StopReason = (typeof STOP_REASONS)[number];

/** Replanning triggers (Part 6 §75). */
export const REPLAN_TRIGGERS = [
  'MAJOR_ENDPOINT_DISCOVERY',
  'NEW_IDENTITY',
  'NEW_AUTHENTICATION_BEHAVIOR',
  'NEW_WORKFLOW',
  'NEW_OBJECT_IDENTIFIER',
  'STRONG_ANOMALY',
  'HYPOTHESIS_CONFIRMED',
  'HYPOTHESIS_DISPROVED',
  'NEW_SOURCE_CODE',
  'IMPORTANT_KNOWLEDGE_RESULT',
  'BUDGET_THRESHOLD',
  'REPEATED_FAILURE',
  'VERIFICATION_RESULT',
  'MANUAL',
] as const;
export type ReplanTrigger = (typeof REPLAN_TRIGGERS)[number];

/** Operating modes of the autonomous engine (Part 6 §2). */
export const AUTONOMOUS_MODES = ['RECON_MODE', 'PENTEST_MODE', 'CTF_MODE'] as const;
export type AutonomousMode = (typeof AUTONOMOUS_MODES)[number];

/** Engine action risk levels (Part 6 §49). Deterministic policy, never model
 *  output. */
export const ENGINE_RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type EngineRiskLevel = (typeof ENGINE_RISK_LEVELS)[number];

/** Recovery policies for expired task leases (Part 6 §55). Potentially
 * state-changing operations are NEVER blindly retried. */
export const RECOVERY_POLICIES = ['SAFE_RETRY', 'RESUME', 'MARK_FAILED', 'RECOMPILE'] as const;
export type RecoveryPolicy = (typeof RECOVERY_POLICIES)[number];

/** Extended finding lifecycle (Part 6 §58, replacing the Part 2 §55 enum):
 * CANDIDATE findings require verification evidence before becoming VERIFIED.
 * PROPOSED/CONFIRMED remain as the Part 2 promotion-ladder aliases written by
 * hypothesis promotion. */
export const FINDING_STATUSES = [
  'PROPOSED',
  'CONFIRMED',
  'REJECTED',
  'CANDIDATE',
  'VERIFIED',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];
/** Finding confidence levels (Part 6 §28). Confidence is NOT severity. */
export const CONFIDENCE_LEVELS = ['HIGH', 'MEDIUM', 'LOW'] as const;
export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];

/** Finding categories (Part 6 §58). Aligned with hypothesis taxonomy. */
export const FINDING_CATEGORIES = [
  ...SECURITY_TAXONOMY,
  'CTF_TECHNIQUE',
  'UNKNOWN',
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];
