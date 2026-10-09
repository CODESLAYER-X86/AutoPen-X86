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

export const TOOL_CAPABILITIES = [
  'READ_ONLY',
  'NETWORK',
  'BROWSER',
  'MUTATION',
  'AUTHENTICATED',
  'DESTRUCTIVE',
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
export const FINDING_STATUSES = ['PROPOSED', 'CONFIRMED', 'REJECTED'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

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

export const PLATFORM_VERSION = '0.3.0-part3';
export const PLATFORM_NAME = 'Aegis Platform';
