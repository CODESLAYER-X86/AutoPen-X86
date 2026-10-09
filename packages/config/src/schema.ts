/**
 * Configuration schema (spec §6). Every environment variable read by the
 * application is declared exactly once here and validated at startup.
 * Failing validation aborts the process with a ConfigurationError.
 *
 * IMPORTANT: raw secret VALUES (e.g. GOOGLE_API_KEY) are intentionally NOT
 * part of the config object. Providers read them directly from the
 * environment; config only carries `configured: true/false` flags.
 */
import { z } from 'zod';

const portSchema = z.coerce.number().int().min(1).max(65535);
const positiveInt = z.coerce.number().int().min(1);

export const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  APP_NAME: z.string().min(1).max(200).default('Aegis Platform'),
  APP_PORT: portSchema.default(4000),
  APP_LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  DATABASE_URL: z
    .string()
    .regex(/^postgres(ql)?:\/\/.+/i, 'DATABASE_URL must be a postgres:// connection string')
    .default('postgres://postgres:postgres@127.0.0.1:5433/aegis'),
  TEST_DATABASE_URL: z
    .string()
    .regex(/^postgres(ql)?:\/\/.+/i)
    .default('postgres://postgres:postgres@127.0.0.1:5433/aegis_test'),
  DATABASE_POOL_MAX: positiveInt.default(10),

  AUTH_SESSION_TTL_HOURS: positiveInt.default(24),
  AUTH_RATE_LIMIT_MAX: positiveInt.default(20),

  STRATEGIC_MODEL_PROVIDER: z.enum(['mock', 'google']).default('mock'),
  STRATEGIC_MODEL_ID: z.string().min(1).max(200).default('mock-strategic-1'),
  TACTICAL_MODEL_PROVIDER: z.enum(['mock', 'google']).default('mock'),
  TACTICAL_MODEL_ID: z.string().min(1).max(200).default('mock-tactical-1'),
  MODEL_REQUEST_TIMEOUT_MS: positiveInt.default(60_000),

  RATE_LIMIT_WINDOW_MS: positiveInt.default(60_000),
  RATE_LIMIT_MAX_REQUESTS: positiveInt.default(300),

  QUEUE_PROVIDER: z.enum(['memory']).default('memory'),

  STORAGE_PROVIDER: z.enum(['local']).default('local'),
  STORAGE_LOCAL_PATH: z.string().min(1).default('./data/artifacts'),

  SECRET_STORE_PATH: z.string().min(1).default('./data/secrets/secrets.json'),
  SECRET_STORE_MASTER_KEY: z.string().optional(),

  BROWSER_ENABLED: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),

  HTTP_TIMEOUT_MS: positiveInt.default(15_000),
  HTTP_MAX_BODY_BYTES: positiveInt.default(1_048_576),

  CORS_ORIGINS: z.string().default('http://localhost:5173'),

  DESTRUCTIVE_ACTIONS_ALLOWED_DEFAULT: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),

  // Part 3: the HTTP + browser interaction tools are implemented — enabled
  // by default; operators can still opt out per deployment.
  FEATURE_TOOLS_HTTP: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(true),
  FEATURE_TOOLS_BROWSER: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(true),
  FEATURE_KNOWLEDGE_SEARCH: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    // Part 5 implements the knowledge subsystem — enabled by default;
    // operators can still opt out per deployment.
    .default(true),
  FEATURE_REPORTING: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    // Part 7 implements verification, reporting and evaluation — enabled by
    // default; operators can opt out per deployment.
    .default(true),
  FEATURE_EVALUATION: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(true),
  // Part 4: the security reasoning engine is implemented — enabled by
  // default; operators can opt out per deployment.
  FEATURE_SECURITY_REASONING: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(true),

  // --- Part 2: Agent Operating System tunables (spec §37-§40, §54, §66) ---
  AGENT_MAX_CYCLES: positiveInt.default(40),
  AGENT_MAX_IDLE_CYCLES: positiveInt.default(3),
  AGENT_IDLE_BACKOFF_MS: positiveInt.default(150),
  AGENT_MAX_WAIT_MS: positiveInt.default(5000),
  AGENT_MAX_CONCURRENT_TASKS: positiveInt.default(2),
  AGENT_WORKER_MAX_TURNS: positiveInt.default(24),
  AGENT_WORKER_MAX_OUTPUT_TOKENS: positiveInt.default(2048),

  AGENT_QUOTA_RPM: positiveInt.default(60),
  AGENT_QUOTA_INPUT_TPM: positiveInt.default(120000),
  AGENT_QUOTA_OUTPUT_TPM: positiveInt.default(16000),
  AGENT_QUOTA_RPD: positiveInt.default(2000),

  AGENT_TOKEN_BUDGET_LEADER: positiveInt.default(400000),
  AGENT_TOKEN_BUDGET_WORKER: positiveInt.default(1200000),
  AGENT_TOKEN_BUDGET_KNOWLEDGE: positiveInt.default(100000),
  AGENT_TOKEN_BUDGET_SUMMARIZATION: positiveInt.default(50000),
  AGENT_TOKEN_BUDGET_VERIFICATION: positiveInt.default(150000),

  AGENT_ENGAGEMENT_MAX_MODEL_CALLS: z.coerce.number().int().min(1).optional(),
  AGENT_ENGAGEMENT_MAX_MODEL_TOKENS: z.coerce.number().int().min(1).optional(),
  AGENT_ENGAGEMENT_MAX_NETWORK_REQUESTS: z.coerce.number().int().min(1).optional(),
  AGENT_ENGAGEMENT_MAX_DURATION_SECONDS: z.coerce.number().int().min(1).optional(),

  // --- Part 4: Security Reasoning Engine resource limits (spec §113) ---
  REASONING_MAX_GRAPH_NODES: positiveInt.default(5000),
  REASONING_MAX_GRAPH_EDGES: positiveInt.default(20000),
  REASONING_MAX_SIGNALS: positiveInt.default(5000),
  REASONING_MAX_PARAMETERS: positiveInt.default(10000),
  REASONING_MAX_ENDPOINTS: positiveInt.default(5000),
  REASONING_MAX_OBJECTS: positiveInt.default(2000),
  REASONING_MAX_EXAMPLE_VALUES: positiveInt.default(8),
  REASONING_MAX_COMPARISON_BYTES: positiveInt.default(65536),
  REASONING_MAX_MUTATION_CANDIDATES: positiveInt.default(64),

  // --- Part 5: Knowledge & Web Research (spec Part 5 §11, §27, §62-§63,
  // §65, §69, §82-§83, §95, §107) ---
  KNOWLEDGE_CHUNK_MIN_TOKENS: positiveInt.default(300),
  KNOWLEDGE_CHUNK_MAX_TOKENS: positiveInt.default(800),
  KNOWLEDGE_MAX_PACKET_TOKENS: positiveInt.default(2500),
  KNOWLEDGE_WORKER_PACKET_TOKENS: positiveInt.default(1200),
  KNOWLEDGE_CACHE_TTL_MS: positiveInt.default(300_000),
  KNOWLEDGE_FETCH_MAX_PAGE_BYTES: positiveInt.default(2_097_152),
  KNOWLEDGE_FETCH_MAX_REDIRECTS: positiveInt.default(5),
  KNOWLEDGE_FETCH_TIMEOUT_MS: positiveInt.default(15_000),
  KNOWLEDGE_SYNC_MAX_PAGES: positiveInt.default(25),
  KNOWLEDGE_FETCH_MAX_CONCURRENCY: positiveInt.default(2),
  KNOWLEDGE_RATE_PER_SOURCE_PER_MINUTE: positiveInt.default(10),
  KNOWLEDGE_DAILY_FETCH_BUDGET: positiveInt.default(500),
  KNOWLEDGE_RESEARCH_MAX_SEARCHES: positiveInt.default(3),
  KNOWLEDGE_RESEARCH_MAX_PAGES: positiveInt.default(5),
  KNOWLEDGE_RESEARCH_MAX_BYTES: positiveInt.default(5_242_880),
  KNOWLEDGE_RESEARCH_MAX_TIME_MS: positiveInt.default(60_000),
  KNOWLEDGE_RESEARCH_MAX_TOKENS: positiveInt.default(6000),
  KNOWLEDGE_EMBEDDING_PROVIDER: z.enum(['hash', 'google', 'none']).default('hash'),
  KNOWLEDGE_EMBEDDING_MODEL: z.string().min(1).max(128).default('aegis-hash-256-v1'),
  KNOWLEDGE_EMBEDDING_DIMENSION: positiveInt.default(256),
  KNOWLEDGE_SEMANTIC_WEIGHT: z.coerce.number().min(0).max(2).default(1.0),
  KNOWLEDGE_KEYWORD_WEIGHT: z.coerce.number().min(0).max(2).default(1.0),
  KNOWLEDGE_TRUST_WEIGHT: z.coerce.number().min(0).max(2).default(0.5),
  KNOWLEDGE_FRESHNESS_WEIGHT: z.coerce.number().min(0).max(2).default(0.3),
  KNOWLEDGE_CONTEXT_WEIGHT: z.coerce.number().min(0).max(2).default(0.4),
  KNOWLEDGE_SPECIFICITY_WEIGHT: z.coerce.number().min(0).max(2).default(0.2),
  KNOWLEDGE_DUPLICATE_PENALTY: z.coerce.number().min(0).max(1).default(0.15),
  KNOWLEDGE_ALLOW_LOOPBACK: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),

  // --- Part 6: Autonomous Pentest & CTF Engine (spec Part 6 §5, §17, §40-§42,
  // §48-§51, §55, §65-§66, §75, §77-§78) ---
  FEATURE_AUTONOMOUS_ENGINE: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    // Part 6 implements the autonomous engine — enabled by default.
    .default(true),
  AUTONOMOUS_MAX_REPLANS: positiveInt.default(6),
  AUTONOMOUS_MAINTENANCE_INTERVAL_MS: positiveInt.default(2500),
  AUTONOMOUS_RECON_MAX_TASKS: positiveInt.default(12),
  AUTONOMOUS_RECON_MAX_PATHS_PER_TARGET: positiveInt.default(8),
  AUTONOMOUS_CANDIDATE_BATCH: positiveInt.default(6),
  AUTONOMOUS_BRANCH_LIMIT: positiveInt.default(8),
  AUTONOMOUS_HYPOTHESIS_LIMIT: positiveInt.default(12),
  AUTONOMOUS_TASK_LEASE_MS: positiveInt.default(120_000),
  AUTONOMOUS_LEASE_SWEEP_INTERVAL_MS: positiveInt.default(15_000),
  AUTONOMOUS_STOP_MIN_TESTS: positiveInt.default(3),
  AUTONOMOUS_STOP_MIN_INFORMATION_GAIN: z.coerce.number().min(0).max(1).default(0.05),
  AUTONOMOUS_STOP_MAX_CONSECUTIVE_FAILURES: positiveInt.default(4),
  AUTONOMOUS_FLAG_PATTERNS: z
    .string()
    .min(1)
    // Semicolon-separated: regex bodies contain commas ({4,128} quantifier).
    .default('flag\\{[A-Za-z0-9_-]{4,128}\\};CTF\\{[A-Za-z0-9_-]{4,128}\\};aegis\\{[A-Za-z0-9_-]{4,128}\\}'),
  AUTONOMOUS_BUDGET_RECON_SHARE: z.coerce.number().min(0.05).max(0.9).default(0.4),
  AUTONOMOUS_BUDGET_TESTING_SHARE: z.coerce.number().min(0.05).max(0.9).default(0.45),
  AUTONOMOUS_TIMELINE_LIMIT: positiveInt.default(200),
  AUTONOMOUS_MAX_KNOWLEDGE_QUERY_REPEATS: positiveInt.default(2),

  // --- Part 7: Verification, Reporting & Evaluation tunables (spec Part 7
  // §15, §24, §29, §33, §65, §71-§72, §89) ---
  REPORTING_CONFIDENCE_HIGH_THRESHOLD: z.coerce.number().min(0.5).max(0.99).default(0.75),
  REPORTING_CONFIDENCE_MEDIUM_THRESHOLD: z.coerce.number().min(0.1).max(0.7).default(0.45),
  REPORTING_HIGH_RISK_CONFIDENCE_THRESHOLD: z.coerce.number().min(0.5).max(0.99).default(0.8),
  REPORTING_MAX_FINDINGS_PER_REPORT: positiveInt.default(500),
  REPORTING_MAX_EVIDENCE_PER_FINDING: positiveInt.default(6),
  REPORTING_EVIDENCE_EXCERPT_BYTES: positiveInt.default(600),
  REPORTING_REQUIRE_VERIFIED_FOR_REPORT: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(true),
  EVALUATION_MAX_SCENARIOS_PER_RUN: positiveInt.default(32),
  EVALUATION_REGRESSION_PRECISION_DROP_PCT: z.coerce.number().min(0).max(50).default(5),
  EVALUATION_REGRESSION_RECALL_DROP_PCT: z.coerce.number().min(0).max(50).default(10),
  EVALUATION_REGRESSION_FPR_RISE_PCT: z.coerce.number().min(0).max(50).default(3),
});

export type EnvRaw = z.infer<typeof EnvSchema>;

export interface AppConfig {
  app: {
    name: string;
    env: 'development' | 'test' | 'production';
    port: number;
    logLevel: 'debug' | 'info' | 'warn' | 'error';
  };
  database: { url: string; testUrl: string; poolMax: number };
  auth: { sessionTtlHours: number; rateLimitMax: number };
  models: {
    strategic: { provider: 'mock' | 'google'; modelId: string };
    tactical: { provider: 'mock' | 'google'; modelId: string };
    requestTimeoutMs: number;
    googleApiKeyConfigured: boolean;
  };
  rateLimits: { windowMs: number; maxRequests: number };
  queue: { provider: 'memory' };
  storage: { provider: 'local'; localPath: string };
  secretStore: { path: string; masterKey?: string };
  browser: { enabled: boolean };
  http: { timeoutMs: number; maxBodyBytes: number };
  security: { corsOrigins: string[]; destructiveActionsAllowedDefault: boolean };
  features: {
    toolsHttp: boolean;
    toolsBrowser: boolean;
    knowledgeSearch: boolean;
    reporting: boolean;
    securityReasoning: boolean;
    autonomousEngine: boolean;
    evaluation: boolean;
  };
  /** Part 4: reasoning engine resource limits (spec §113). */
  reasoning: {
    maxGraphNodes: number;
    maxGraphEdges: number;
    maxSignals: number;
    maxParameters: number;
    maxEndpoints: number;
    maxObjects: number;
    maxExampleValues: number;
    maxComparisonBytes: number;
    maxMutationCandidates: number;
  };
  /** Part 5: knowledge & web research limits (spec Part 5 §62, §27, §69, §83). */
  knowledge: {
    chunkMinTokens: number;
    chunkMaxTokens: number;
    maxPacketTokens: number;
    workerPacketTokens: number;
    cacheTtlMs: number;
    fetch: {
      maxPageBytes: number;
      maxRedirects: number;
      timeoutMs: number;
      syncMaxPages: number;
      maxConcurrency: number;
      ratePerSourcePerMinute: number;
      dailyFetchBudget: number;
      allowLoopback: boolean;
    };
    research: {
      maxSearches: number;
      maxPages: number;
      maxBytes: number;
      maxTimeMs: number;
      maxTokens: number;
    };
    embedding: {
      provider: 'hash' | 'google' | 'none';
      model: string;
      dimension: number;
    };
    weights: {
      semantic: number;
      keyword: number;
      trust: number;
      freshness: number;
      context: number;
      specificity: number;
      duplicatePenalty: number;
    };
  };
  /** Part 2: Agent OS tunables. */
  agent: {
    loop: {
      maxCycles: number;
      maxIdleCycles: number;
      idleBackoffMs: number;
      maxWaitMs: number;
      maxConcurrentTasks: number;
    };
    worker: { maxTurns: number; maxOutputTokens: number };
    quota: {
      requestsPerMinute: number;
      inputTokensPerMinute: number;
      outputTokensPerMinute: number;
      requestsPerDay: number;
    };
    tokenBudgets: {
      leader: number;
      worker: number;
      knowledge: number;
      summarization: number;
      verification: number;
    };
    engagementBudgetDefaults: {
      maxModelCalls: number | null;
      maxModelTokens: number | null;
      maxNetworkRequests: number | null;
      maxDurationSeconds: number | null;
    };
  };
  /** Part 6: autonomous engine tunables (spec Part 6 §42, §55, §65, §78). */
  autonomous: {
    maxReplans: number;
    maintenanceIntervalMs: number;
    reconMaxTasks: number;
    reconMaxPathsPerTarget: number;
    candidateBatch: number;
    branchLimit: number;
    hypothesisLimit: number;
    taskLeaseMs: number;
    leaseSweepIntervalMs: number;
    stopMinTests: number;
    stopMinInformationGain: number;
    stopMaxConsecutiveFailures: number;
    flagPatterns: string;
    budgetReconShare: number;
    budgetTestingShare: number;
    timelineLimit: number;
    maxKnowledgeQueryRepeats: number;
  };
  /** Part 7: verification, reporting & evaluation tunables. */
  reporting: {
    confidenceHighThreshold: number;
    confidenceMediumThreshold: number;
    highRiskConfidenceThreshold: number;
    maxFindingsPerReport: number;
    maxEvidencePerFinding: number;
    evidenceExcerptBytes: number;
    requireVerifiedForReport: boolean;
  };
  evaluation: {
    maxScenariosPerRun: number;
    regressionPrecisionDropPct: number;
    regressionRecallDropPct: number;
    regressionFprRisePct: number;
  };
}
