/**
 * Retry policy (spec Part 2 §43-§44).
 *
 * Retry transient failures (network, provider timeout, temporary quota,
 * browser startup). NEVER blindly retry: scope violations, invalid schema,
 * invalid target, permission denied, unsupported operation.
 * Exponential backoff with bounded attempts.
 */
import {
  AuthenticationError,
  AuthorizationError,
  DatabaseError,
  NotImplementedError,
  QuotaError,
  ScopeViolationError,
  TimeoutError,
  ValidationError,
  isPlatformError,
} from '@aegis/shared';

export interface ErrorClassification {
  retryable: boolean;
  code: string;
  category: string;
  /** Permanent failures never retry (§43.6). */
  permanent: boolean;
}

const NON_RETRYABLE_CODES = new Set([
  'TOOL_INPUT_INVALID',
  'TOOL_OUTPUT_INVALID',
  'TOOL_NOT_FOUND',
  'TOOL_NOT_IMPLEMENTED',
  'LEADER_DECISION_INVALID',
  'WORKER_OUTPUT_INVALID',
  'WORKER_TURN_INVALID',
]);

export function classifyError(error: unknown): ErrorClassification {
  if (isPlatformError(error)) {
    const permanent =
      error instanceof ValidationError ||
      error instanceof ScopeViolationError ||
      error instanceof AuthorizationError ||
      error instanceof AuthenticationError ||
      error instanceof NotImplementedError ||
      NON_RETRYABLE_CODES.has(error.code);
    const retryable =
      !permanent &&
      (error instanceof TimeoutError ||
        error instanceof QuotaError ||
        error instanceof DatabaseError ||
        error.category === 'NETWORK' ||
        error.category === 'MODEL' ||
        error.category === 'BROWSER');
    return {
      retryable,
      code: error.code,
      category: error.category,
      permanent,
    };
  }
  // Unknown errors (fetch failures etc.) are treated as transient network
  // issues — the safest retryable assumption.
  return { retryable: true, code: 'UNKNOWN_ERROR', category: 'INTERNAL', permanent: false };
}

export interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  onRetry?: (attempt: number, error: unknown, delayMs: number) => void;
}

const DEFAULTS: Required<Omit<RetryOptions, 'onRetry'>> = {
  maxAttempts: 3,
  baseDelayMs: 400,
  maxDelayMs: 4_000,
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Runs an operation with bounded exponential-backoff retries. A thrown
 * non-retryable error propagates immediately; retryable errors retry up to
 * maxAttempts, then propagate.
 */
export async function withRetries<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const opts = { ...DEFAULTS, ...options };
  let lastError: unknown;
  for (let attempt = 1; attempt <= opts.maxAttempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      const classification = classifyError(error);
      if (!classification.retryable || attempt === opts.maxAttempts) {
        throw error;
      }
      const delay = Math.min(opts.baseDelayMs * 2 ** (attempt - 1), opts.maxDelayMs);
      options.onRetry?.(attempt, error, delay);
      await sleep(delay);
    }
  }
  throw lastError;
}
