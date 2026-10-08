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

  FEATURE_TOOLS_HTTP: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),
  FEATURE_TOOLS_BROWSER: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),
  FEATURE_KNOWLEDGE_SEARCH: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),
  FEATURE_REPORTING: z
    .union([z.boolean(), z.string()])
    .transform((v) => (typeof v === 'boolean' ? v : ['1', 'true', 'yes', 'on'].includes(v.toLowerCase())))
    .default(false),

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
}
