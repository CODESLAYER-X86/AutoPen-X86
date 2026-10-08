/**
 * Config loader (spec §6): `.env` file + real environment, validated with
 * zod, transformed to a typed AppConfig. Fails fast with ConfigurationError.
 */
import { ConfigurationError } from '@aegis/shared';
import { z } from 'zod';
import { readEnvFile } from './env-file.js';
import { EnvSchema, type AppConfig, type EnvRaw } from './schema.js';

export interface LoadConfigOptions {
  /** Raw environment to use instead of process.env. */
  env?: Record<string, string | undefined>;
  /**
   * Optional .env file path. In development/test the file takes precedence
   * over process.env (operators' local values win over stray shell vars);
   * loading a .env file in production is refused — production must use real
   * environment variables.
   */
  envFile?: string;
}

function stripEmpty(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || value === '') continue;
    out[key] = value;
  }
  return out;
}

function toAppConfig(raw: EnvRaw, googleApiKeyConfigured: boolean): AppConfig {
  return {
    app: {
      name: raw.APP_NAME,
      env: raw.NODE_ENV,
      port: raw.APP_PORT,
      logLevel: raw.APP_LOG_LEVEL,
    },
    database: {
      url: raw.DATABASE_URL,
      testUrl: raw.TEST_DATABASE_URL,
      poolMax: raw.DATABASE_POOL_MAX,
    },
    auth: {
      sessionTtlHours: raw.AUTH_SESSION_TTL_HOURS,
      rateLimitMax: raw.AUTH_RATE_LIMIT_MAX,
    },
    models: {
      strategic: { provider: raw.STRATEGIC_MODEL_PROVIDER, modelId: raw.STRATEGIC_MODEL_ID },
      tactical: { provider: raw.TACTICAL_MODEL_PROVIDER, modelId: raw.TACTICAL_MODEL_ID },
      requestTimeoutMs: raw.MODEL_REQUEST_TIMEOUT_MS,
      googleApiKeyConfigured,
    },
    rateLimits: {
      windowMs: raw.RATE_LIMIT_WINDOW_MS,
      maxRequests: raw.RATE_LIMIT_MAX_REQUESTS,
    },
    queue: { provider: raw.QUEUE_PROVIDER },
    storage: { provider: raw.STORAGE_PROVIDER, localPath: raw.STORAGE_LOCAL_PATH },
    secretStore: {
      path: raw.SECRET_STORE_PATH,
      masterKey: raw.SECRET_STORE_MASTER_KEY,
    },
    browser: { enabled: raw.BROWSER_ENABLED },
    http: { timeoutMs: raw.HTTP_TIMEOUT_MS, maxBodyBytes: raw.HTTP_MAX_BODY_BYTES },
    security: {
      corsOrigins: raw.CORS_ORIGINS.split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
      destructiveActionsAllowedDefault: raw.DESTRUCTIVE_ACTIONS_ALLOWED_DEFAULT,
    },
    features: {
      toolsHttp: raw.FEATURE_TOOLS_HTTP,
      toolsBrowser: raw.FEATURE_TOOLS_BROWSER,
      knowledgeSearch: raw.FEATURE_KNOWLEDGE_SEARCH,
      reporting: raw.FEATURE_REPORTING,
    },
    agent: {
      loop: {
        maxCycles: raw.AGENT_MAX_CYCLES,
        maxIdleCycles: raw.AGENT_MAX_IDLE_CYCLES,
        idleBackoffMs: raw.AGENT_IDLE_BACKOFF_MS,
        maxWaitMs: raw.AGENT_MAX_WAIT_MS,
        maxConcurrentTasks: raw.AGENT_MAX_CONCURRENT_TASKS,
      },
      worker: {
        maxTurns: raw.AGENT_WORKER_MAX_TURNS,
        maxOutputTokens: raw.AGENT_WORKER_MAX_OUTPUT_TOKENS,
      },
      quota: {
        requestsPerMinute: raw.AGENT_QUOTA_RPM,
        inputTokensPerMinute: raw.AGENT_QUOTA_INPUT_TPM,
        outputTokensPerMinute: raw.AGENT_QUOTA_OUTPUT_TPM,
        requestsPerDay: raw.AGENT_QUOTA_RPD,
      },
      tokenBudgets: {
        leader: raw.AGENT_TOKEN_BUDGET_LEADER,
        worker: raw.AGENT_TOKEN_BUDGET_WORKER,
        knowledge: raw.AGENT_TOKEN_BUDGET_KNOWLEDGE,
        summarization: raw.AGENT_TOKEN_BUDGET_SUMMARIZATION,
        verification: raw.AGENT_TOKEN_BUDGET_VERIFICATION,
      },
      engagementBudgetDefaults: {
        maxModelCalls: raw.AGENT_ENGAGEMENT_MAX_MODEL_CALLS ?? null,
        maxModelTokens: raw.AGENT_ENGAGEMENT_MAX_MODEL_TOKENS ?? null,
        maxNetworkRequests: raw.AGENT_ENGAGEMENT_MAX_NETWORK_REQUESTS ?? null,
        maxDurationSeconds: raw.AGENT_ENGAGEMENT_MAX_DURATION_SECONDS ?? null,
      },
    },
  };
}

export function loadConfig(options: LoadConfigOptions = {}): AppConfig {
  const sourceEnv = options.env ?? process.env;
  let fileEnv: Record<string, string> = {};
  if (options.envFile) {
    const nodeEnv = (sourceEnv.NODE_ENV ?? process.env.NODE_ENV ?? 'development').toLowerCase();
    if (nodeEnv === 'production') {
      throw new ConfigurationError(
        'Loading a .env file is not allowed in production; set real environment variables',
        undefined,
        'ENV_FILE_IN_PRODUCTION',
      );
    }
    fileEnv = readEnvFile(options.envFile);
  }
  // Development semantics: .env file values take precedence over the shell
  // environment (documented in docs/operations/development.md).
  const merged: Record<string, string> = { ...stripEmpty(sourceEnv), ...fileEnv };

  const parsed = EnvSchema.safeParse(merged);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => ({
      variable: issue.path.join('.') || '(root)',
      message: issue.message,
    }));
    throw new ConfigurationError(
      'Invalid configuration: environment validation failed',
      issues,
      'CONFIG_VALIDATION_FAILED',
    );
  }

  // Secrets are read from the raw environment only — never stored in config.
  const googleApiKeyConfigured = Boolean(stripEmpty(sourceEnv).GOOGLE_API_KEY);

  return toAppConfig(parsed.data, googleApiKeyConfigured);
}

/** A summary safe to expose via /api/meta (no secrets, no URLs with credentials). */
export function configSummary(config: AppConfig) {
  return {
    app: { ...config.app },
    models: {
      strategic: { ...config.models.strategic },
      tactical: { ...config.models.tactical },
      googleApiKeyConfigured: config.models.googleApiKeyConfigured,
    },
    features: { ...config.features },
    queue: { provider: config.queue.provider },
    storage: { provider: config.storage.provider },
    browser: { enabled: config.browser.enabled },
  };
}

/** Utility used by tests to validate arbitrary env objects against the schema. */
export function validateEnv(env: Record<string, string | undefined>): z.infer<typeof EnvSchema> {
  const parsed = EnvSchema.safeParse(stripEmpty(env));
  if (!parsed.success) {
    throw new ConfigurationError(
      'Invalid configuration',
      parsed.error.issues.map((issue) => ({ variable: issue.path.join('.'), message: issue.message })),
      'CONFIG_VALIDATION_FAILED',
    );
  }
  return parsed.data;
}

export type { AppConfig };
