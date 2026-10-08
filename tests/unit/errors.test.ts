import { describe, expect, it } from 'vitest';
import {
  AuthenticationError,
  AuthorizationError,
  ConfigurationError,
  DatabaseError,
  EvidenceError,
  ModelError,
  NotFoundError,
  NotImplementedError,
  QuotaError,
  ScopeViolationError,
  TimeoutError,
  ToolError,
  ValidationError,
  isPlatformError,
} from '@aegis/shared';

describe('typed error hierarchy', () => {
  it('maps every category to its documented HTTP status', () => {
    expect(new ConfigurationError('x').statusCode).toBe(500);
    expect(new AuthenticationError().statusCode).toBe(401);
    expect(new AuthorizationError().statusCode).toBe(403);
    expect(new NotFoundError('PROJECT').statusCode).toBe(404);
    expect(new ScopeViolationError('x').statusCode).toBe(422);
    expect(new ValidationError().statusCode).toBe(400);
    expect(new ToolError('x').statusCode).toBe(500);
    expect(new QuotaError().statusCode).toBe(429);
    expect(new ModelError('x').statusCode).toBe(502);
    expect(new DatabaseError('x').statusCode).toBe(500);
    expect(new EvidenceError('x').statusCode).toBe(500);
    expect(new TimeoutError().statusCode).toBe(504);
    expect(new NotImplementedError('x').statusCode).toBe(501);
  });

  it('serialises to a safe JSON shape', () => {
    const error = new ValidationError('bad input', 'BAD', [{ path: 'name' }]);
    expect(error.toJSON()).toEqual({
      code: 'BAD',
      category: 'VALIDATION',
      message: 'bad input',
      details: [{ path: 'name' }],
    });
  });

  it('is identifiable via isPlatformError', () => {
    expect(isPlatformError(new ValidationError('x'))).toBe(true);
    expect(isPlatformError(new Error('plain'))).toBe(false);
    expect(isPlatformError(null)).toBe(false);
  });

  it('carries a cause without leaking it into the public message', () => {
    const cause = new Error('internal details: password=hunter2');
    const error = new DatabaseError('query failed', 'DB', undefined, cause);
    expect(error.message).not.toContain('hunter2');
    expect(error.cause).toBe(cause);
  });
});
