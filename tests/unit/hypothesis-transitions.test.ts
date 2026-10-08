import { describe, expect, it } from 'vitest';
import {
  SaturatingConfidenceStrategy,
  HYPOTHESIS_TRANSITIONS,
  isTerminalHypothesis,
  assertHypothesisTransition,
  DEFAULT_BRANCH_BUDGET,
} from '@aegis/agent';
import { ValidationError, type HypothesisStatus } from '@aegis/shared';

describe('confidence strategy (spec Part 2 §25)', () => {
  const strategy = new SaturatingConfidenceStrategy();

  it('supporting evidence increases confidence with saturation', () => {
    expect(strategy.increase(0.5, 0.4)).toBeCloseTo(0.7);
    expect(strategy.increase(0.5, 0.0 + 0.01)).toBeGreaterThan(0.5);
    // Saturation: repeated support approaches but never exceeds 1.
    let confidence = 0.5;
    for (let i = 0; i < 50; i += 1) confidence = strategy.increase(confidence, 0.3);
    expect(confidence).toBeLessThanOrEqual(1);
    expect(confidence).toBeGreaterThan(0.99);
  });

  it('contradicting evidence decreases confidence proportionally', () => {
    expect(strategy.decrease(0.8, 0.5)).toBeCloseTo(0.4);
    let confidence = 0.9;
    for (let i = 0; i < 50; i += 1) confidence = strategy.decrease(confidence, 0.3);
    expect(confidence).toBeLessThan(0.01);
    expect(confidence).toBeGreaterThanOrEqual(0);
  });

  it('stays inside [0, 1] for extreme inputs', () => {
    expect(strategy.increase(1, 1)).toBeLessThanOrEqual(1);
    expect(strategy.increase(0, 1)).toBeLessThanOrEqual(1);
    expect(strategy.decrease(0, 1)).toBeGreaterThanOrEqual(0);
  });
});

describe('hypothesis status transitions (spec Part 2 §22, §55)', () => {
  it('follows the ladder PROPOSED -> ACTIVE -> TESTING -> SUPPORTED', () => {
    expect(HYPOTHESIS_TRANSITIONS.PROPOSED).toContain('ACTIVE');
    expect(HYPOTHESIS_TRANSITIONS.ACTIVE).toContain('TESTING');
    expect(HYPOTHESIS_TRANSITIONS.TESTING).toContain('SUPPORTED');
  });

  it('CONFIRMED is reachable only from SUPPORTED or TESTING (verification gate, §55)', () => {
    expect(HYPOTHESIS_TRANSITIONS.SUPPORTED).toContain('CONFIRMED');
    expect(HYPOTHESIS_TRANSITIONS.TESTING).toContain('CONFIRMED');
    expect(HYPOTHESIS_TRANSITIONS.ACTIVE).not.toContain('CONFIRMED');
    expect(HYPOTHESIS_TRANSITIONS.PROPOSED).not.toContain('CONFIRMED');
  });

  it('terminal hypotheses cannot revive', () => {
    const terminals: HypothesisStatus[] = ['CONFIRMED', 'DISPROVED', 'ABANDONED'];
    for (const terminal of terminals) {
      expect(isTerminalHypothesis(terminal)).toBe(true);
      expect(HYPOTHESIS_TRANSITIONS[terminal]).toHaveLength(0);
      expect(() => assertHypothesisTransition(terminal, 'ACTIVE')).toThrowError(ValidationError);
    }
  });

  it('branch budgets default to §54 values', () => {
    expect(DEFAULT_BRANCH_BUDGET.maxActiveHypotheses).toBe(12);
    expect(DEFAULT_BRANCH_BUDGET.maxBranchDepth).toBe(4);
    expect(DEFAULT_BRANCH_BUDGET.maxParallelBranches).toBe(4);
  });
});
