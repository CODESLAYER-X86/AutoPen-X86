/**
 * Typed error hierarchy for the entire platform.
 *
 * Rules:
 *  - Every error carries a machine-readable `code`, an `category`, an HTTP
 *    `statusCode`, and an optional structured `details` payload.
 *  - `message` is safe to expose to API clients (no stack traces, no SQL,
 *    no secrets). Internal details go to the structured logger, never to
 *    the response body.
 *  - A failing worker / tool / request must never crash an engagement:
 *    callers are expected to catch typed errors and decide on recovery.
 */

export type ErrorCategory =
  | 'CONFIGURATION'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'SCOPE'
  | 'VALIDATION'
  | 'TOOL'
  | 'NETWORK'
  | 'BROWSER'
  | 'MODEL'
  | 'QUOTA'
  | 'DATABASE'
  | 'EVIDENCE'
  | 'TIMEOUT'
  | 'INTERNAL';

export interface PlatformErrorOptions {
  code: string;
  category: ErrorCategory;
  statusCode: number;
  details?: unknown;
  cause?: unknown;
}

export class PlatformError extends Error {
  readonly code: string;
  readonly category: ErrorCategory;
  readonly statusCode: number;
  readonly details?: unknown;

  constructor(message: string, options: PlatformErrorOptions) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'PlatformError';
    this.code = options.code;
    this.category = options.category;
    this.statusCode = options.statusCode;
    this.details = options.details;
  }

  toJSON(): { code: string; category: ErrorCategory; message: string; details?: unknown } {
    return {
      code: this.code,
      category: this.category,
      message: this.message,
      ...(this.details === undefined ? {} : { details: this.details }),
    };
  }
}

/** Thrown when environment/configuration is invalid at startup. HTTP 500. */
export class ConfigurationError extends PlatformError {
  constructor(message: string, details?: unknown, code = 'CONFIGURATION_ERROR') {
    super(message, { code, category: 'CONFIGURATION', statusCode: 500, details });
  }
}

/** Missing/invalid credentials. HTTP 401. */
export class AuthenticationError extends PlatformError {
  constructor(
    message = 'Authentication required',
    code = 'UNAUTHENTICATED',
    details?: unknown,
  ) {
    super(message, { code, category: 'AUTHENTICATION', statusCode: 401, details });
  }
}

/** Authenticated but not permitted. HTTP 403. */
export class AuthorizationError extends PlatformError {
  constructor(message = 'Not permitted', code = 'FORBIDDEN', details?: unknown) {
    super(message, { code, category: 'AUTHORIZATION', statusCode: 403, details });
  }
}

/**
 * Resource does not exist OR is owned by another user. Deliberately 404 to
 * avoid leaking the existence of resources across tenant boundaries.
 */
export class NotFoundError extends PlatformError {
  constructor(resource = 'RESOURCE', code?: string) {
    super(`${resource}_NOT_FOUND`, {
      code: code ?? `${resource}_NOT_FOUND`,
      category: 'AUTHORIZATION',
      statusCode: 404,
    });
  }
}

/** A target/URL violates the engagement scope. HTTP 422. */
export class ScopeViolationError extends PlatformError {
  constructor(message: string, code = 'SCOPE_VIOLATION', details?: unknown) {
    super(message, { code, category: 'SCOPE', statusCode: 422, details });
  }
}

/** Schema-invalid input. HTTP 400. */
export class ValidationError extends PlatformError {
  constructor(message = 'Validation failed', code = 'VALIDATION_FAILED', details?: unknown) {
    super(message, { code, category: 'VALIDATION', statusCode: 400, details });
  }
}

export class ToolError extends PlatformError {
  constructor(message: string, code = 'TOOL_ERROR', details?: unknown) {
    super(message, { code, category: 'TOOL', statusCode: 500, details });
  }
}

export class NetworkError extends PlatformError {
  constructor(message: string, code = 'NETWORK_ERROR', details?: unknown) {
    super(message, { code, category: 'NETWORK', statusCode: 502, details });
  }
}

export class BrowserError extends PlatformError {
  constructor(message: string, code = 'BROWSER_ERROR', details?: unknown) {
    super(message, { code, category: 'BROWSER', statusCode: 500, details });
  }
}

export class ModelError extends PlatformError {
  constructor(message: string, code = 'MODEL_ERROR', details?: unknown) {
    super(message, { code, category: 'MODEL', statusCode: 502, details });
  }
}

export class QuotaError extends PlatformError {
  constructor(message = 'Rate or quota limit exceeded', code = 'QUOTA_EXCEEDED', details?: unknown) {
    super(message, { code, category: 'QUOTA', statusCode: 429, details });
  }
}

export class DatabaseError extends PlatformError {
  constructor(message: string, code = 'DATABASE_ERROR', details?: unknown, cause?: unknown) {
    super(message, { code, category: 'DATABASE', statusCode: 500, details, cause });
  }
}

export class EvidenceError extends PlatformError {
  constructor(message: string, code = 'EVIDENCE_ERROR', details?: unknown) {
    super(message, { code, category: 'EVIDENCE', statusCode: 500, details });
  }
}

export class TimeoutError extends PlatformError {
  constructor(message = 'Operation timed out', code = 'TIMEOUT', details?: unknown) {
    super(message, { code, category: 'TIMEOUT', statusCode: 504, details });
  }
}

/** A subsystem that is deliberately not implemented yet. HTTP 501. */
export class NotImplementedError extends PlatformError {
  constructor(message: string, code = 'NOT_IMPLEMENTED', details?: unknown) {
    super(message, { code, category: 'INTERNAL', statusCode: 501, details });
  }
}

export function isPlatformError(value: unknown): value is PlatformError {
  return value instanceof PlatformError;
}
