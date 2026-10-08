/**
 * Worker-local retry policy (spec Part 2 §44). Mirrors the agent service's
 * retry module — kept local to avoid a circular package dependency
 * (agent depends on worker-runtime for the packet type).
 */
import {
  AuthenticationError,
  AuthorizationError,
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
  permanent: boolean;
}

const NON_RETRYABLE_CODES = new Set([
  'TOOL_INPUT_INVALID',
  'TOOL_OUTPUT_INVALID',
  'TOOL_NOT_FOUND',
  'TOOL_NOT_IMPLEMENTED',
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
        error.category === 'NETWORK' ||
        error.category === 'MODEL' ||
        error.category === 'BROWSER');
    return { retryable, code: error.code, category: error.category, permanent };
  }
  return { retryable: true, code: 'UNKNOWN_ERROR', category: 'INTERNAL', permanent: false };
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function withRetries<T>(
  operation: () => Promise<T>,
  options: { maxAttempts?: number; baseDelayMs?: number; maxDelayMs?: number } = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const baseDelayMs = options.baseDelayMs ?? 400;
  const maxDelayMs = options.maxDelayMs ?? 4_000;
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      const classification = classifyError(error);
      if (!classification.retryable || attempt === maxAttempts) {
        throw error;
      }
      await sleep(Math.min(baseDelayMs * 2 ** (attempt - 1), maxDelayMs));
    }
  }
  throw lastError;
}
