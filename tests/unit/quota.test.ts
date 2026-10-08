import { describe, expect, it } from 'vitest';
import {
  QuotaManager,
  TokenBudgeter,
  estimateTokens,
  DEFAULT_QUOTA_LIMITS,
} from '@aegis/agent';

describe('quota manager (spec Part 2 §37, §39-§40)', () => {
  it('allows dispatch under the limits', () => {
    const quota = new QuotaManager({ requestsPerMinute: 5, inputTokensPerMinute: 1000 });
    const result = quota.canDispatch(200, 100);
    expect(result.allowed).toBe(true);
  });

  it('blocks dispatch when input TPM would be exceeded', () => {
    const quota = new QuotaManager({ inputTokensPerMinute: 1000 });
    quota.recordUsage(900, 0);
    const result = quota.canDispatch(200, 10);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain('Input TPM');
      expect(result.retryAfterMs).toBeGreaterThan(0);
    }
  });

  it('blocks dispatch when output TPM would be exceeded', () => {
    const quota = new QuotaManager({ outputTokensPerMinute: 500 });
    quota.recordUsage(0, 400);
    const result = quota.canDispatch(10, 200);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toContain('Output TPM');
  });

  it('blocks dispatch when RPM would be exceeded', () => {
    const quota = new QuotaManager({ requestsPerMinute: 3 });
    quota.recordUsage(10, 10);
    quota.recordUsage(10, 10);
    quota.recordUsage(10, 10);
    const result = quota.canDispatch(10, 10);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toContain('RPM');
  });

  it('blocks dispatch when the daily request quota is exhausted', () => {
    const quota = new QuotaManager({ requestsPerDay: 2 });
    quota.recordUsage(0, 0);
    quota.recordUsage(0, 0);
    const result = quota.canDispatch(1, 1);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toContain('Daily request quota');
  });

  it('frees capacity when the minute window slides', () => {
    const quota = new QuotaManager({ requestsPerMinute: 1, inputTokensPerMinute: 10_000 });
    quota.recordUsage(100, 0, Date.now() - 61_000); // outside the window
    const result = quota.canDispatch(100, 0);
    expect(result.allowed).toBe(true);
  });

  it('snapshots expose current pressure for the scheduler', () => {
    const quota = new QuotaManager();
    quota.recordUsage(500, 100);
    const snap = quota.snapshot();
    expect(snap.requestsPerMinute).toBe(1);
    expect(snap.inputTokensPerMinute).toBe(500);
    expect(snap.outputTokensPerMinute).toBe(100);
    expect(snap.requestsPerDay).toBe(1);
    expect(snap.limits).toEqual(DEFAULT_QUOTA_LIMITS);
  });

  it('all numbers are configurable — defaults are not permanent', () => {
    const quota = new QuotaManager({
      requestsPerMinute: 1,
      inputTokensPerMinute: 1,
      outputTokensPerMinute: 1,
      requestsPerDay: 1,
    });
    expect(quota.limitSet).toEqual({
      requestsPerMinute: 1,
      inputTokensPerMinute: 1,
      outputTokensPerMinute: 1,
      requestsPerDay: 1,
    });
  });
});

describe('token budgeter (spec Part 2 §38-§39)', () => {
  it('keeps separate budgets per purpose', () => {
    const budgets = new TokenBudgeter({ leader: 1000, worker: 5000 });
    budgets.record('leader', 900, 0);
    expect(budgets.remaining('leader')).toBe(100);
    expect(budgets.remaining('worker')).toBe(5000);
  });

  it('refuses to intentionally exceed a budget, with safety margin (§39)', () => {
    const budgets = new TokenBudgeter({ worker: 1000 });
    const result = budgets.canSpend('worker', 500, 400);
    // (500 + 400) * 1.2 = 1080 > 1000 -> refused.
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toContain('worker');

    const fine = budgets.canSpend('worker', 300, 200); // (500) * 1.2 = 600 <= 1000
    expect(fine.allowed).toBe(true);
  });

  it('tracks usage per purpose for observability', () => {
    const budgets = new TokenBudgeter();
    budgets.record('leader', 100, 50);
    budgets.record('verification', 40, 10);
    const usage = budgets.usage();
    expect(usage.leader.input).toBe(100);
    expect(usage.leader.output).toBe(50);
    expect(usage.verification.input).toBe(40);
    expect(usage.verification.budget).toBeGreaterThan(0);
  });

  it('estimates tokens from text length', () => {
    expect(estimateTokens('abcd')).toBe(1);
    expect(estimateTokens('abc')).toBe(1);
    expect(estimateTokens('a'.repeat(400))).toBe(100);
  });
});
