import { describe, expect, it, vi } from 'vitest';
import { classifyError, withRetries } from '@aegis/agent';
import {
  AuthenticationError,
  AuthorizationError,
  ModelError,
  NetworkError,
  NotImplementedError,
  QuotaError,
  ScopeViolationError,
  TimeoutError,
  ToolError,
  ValidationError,
} from '@aegis/shared';

describe('retry classification (spec Part 2 §44)', () => {
  it('classifies transient errors as retryable', () => {
    expect(classifyError(new TimeoutError('t')).retryable).toBe(true);
    expect(classifyError(new QuotaError()).retryable).toBe(true);
    expect(classifyError(new NetworkError('n')).retryable).toBe(true);
    expect(classifyError(new ModelError('m')).retryable).toBe(true);
    expect(classifyError(new Error('fetch failed')).retryable).toBe(true);
  });

  it('classifies permanent errors as never-retryable', () => {
    expect(classifyError(new ValidationError('bad input')).permanent).toBe(true);
    expect(classifyError(new ScopeViolationError('s')).permanent).toBe(true);
    expect(classifyError(new AuthorizationError()).permanent).toBe(true);
    expect(classifyError(new AuthenticationError()).permanent).toBe(true);
    expect(classifyError(new NotImplementedError('n')).permanent).toBe(true);
    expect(classifyError(new ToolError('x', 'TOOL_INPUT_INVALID')).permanent).toBe(true);
    expect(classifyError(new ToolError('x', 'TOOL_NOT_FOUND')).permanent).toBe(true);
  });

  it('retries transient failures with bounded attempts and eventual success', async () => {
    let attempts = 0;
    const result = await withRetries(
      async () => {
        attempts += 1;
        if (attempts < 3) throw new TimeoutError('transient');
        return 'ok';
      },
      { maxAttempts: 5, baseDelayMs: 1 },
    );
    expect(result).toBe('ok');
    expect(attempts).toBe(3);
  });

  it('propagates permanent failures immediately without retry', async () => {
    const spy = vi.fn(async () => {
      throw new ValidationError('permanent');
    });
    await expect(
      withRetries(spy, { maxAttempts: 5, baseDelayMs: 1 }),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('gives up after maxAttempts on persistent transient errors', async () => {
    const spy = vi.fn(async () => {
      throw new TimeoutError('always down');
    });
    await expect(withRetries(spy, { maxAttempts: 3, baseDelayMs: 1 })).rejects.toBeInstanceOf(
      TimeoutError,
    );
    expect(spy).toHaveBeenCalledTimes(3);
  });

  it('uses exponential backoff capped at the maximum', async () => {
    const delays: number[] = [];
    let attempts = 0;
    await withRetries(
      async () => {
        attempts += 1;
        if (attempts < 4) throw new TimeoutError('t');
        return 1;
      },
      {
        maxAttempts: 5,
        baseDelayMs: 2,
        maxDelayMs: 5,
        onRetry: (_attempt, _error, delayMs) => delays.push(delayMs),
      },
    );
    expect(delays).toEqual([2, 4, 5]);
  });
});
