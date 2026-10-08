import { describe, expect, it } from 'vitest';
import { computePriority, quotaAdjustedPriority, DEFAULT_PRIORITY_WEIGHTS } from '@aegis/agent';

const base = {
  hypothesisConfidence: 0.5,
  potentialImpact: 0.5,
  expectedInformationGain: 0.5,
  testCost: 0.3,
  scopeRelevance: 1,
  novelty: 1,
  dependencyReadiness: 1,
  previousFailurePenalty: 0,
};

describe('task priority scoring (spec Part 2 §20-§21)', () => {
  it('ranks expected information gain above impact and confidence', () => {
    const highGain = computePriority({ ...base, expectedInformationGain: 1 });
    const highImpact = computePriority({ ...base, potentialImpact: 1, expectedInformationGain: 0 });
    const highConfidence = computePriority({
      ...base,
      hypothesisConfidence: 1,
      expectedInformationGain: 0,
    });
    expect(highGain).toBeGreaterThan(highImpact);
    expect(highGain).toBeGreaterThan(highConfidence);
  });

  it('a low-impact observation that unlocks the surface can outrank high severity', () => {
    // §20: do not use severity alone. The unlock test (high gain, low
    // impact) must outrank a high-impact low-gain generic scan.
    const unlockTest = computePriority({
      ...base,
      potentialImpact: 0.2,
      expectedInformationGain: 0.95,
    });
    const severeGenericScan = computePriority({
      ...base,
      potentialImpact: 1,
      expectedInformationGain: 0.1,
      testCost: 0.8,
    });
    expect(unlockTest).toBeGreaterThan(severeGenericScan);
  });

  it('test cost and previous failures reduce priority', () => {
    const cheap = computePriority({ ...base, testCost: 0 });
    const expensive = computePriority({ ...base, testCost: 1 });
    expect(cheap).toBeGreaterThan(expensive);

    const clean = computePriority({ ...base, previousFailurePenalty: 0 });
    const failedBefore = computePriority({ ...base, previousFailurePenalty: 1 });
    expect(clean).toBeGreaterThan(failedBefore);
  });

  it('dependency readiness and scope relevance matter', () => {
    const ready = computePriority({ ...base, dependencyReadiness: 1 });
    const blocked = computePriority({ ...base, dependencyReadiness: 0 });
    expect(ready).toBeGreaterThan(blocked);

    const inScope = computePriority({ ...base, scopeRelevance: 1 });
    const outOfScope = computePriority({ ...base, scopeRelevance: 0 });
    expect(inScope).toBeGreaterThan(outOfScope);
  });

  it('clamps to 0..1 and weights sum to a sane budget', () => {
    expect(computePriority({ ...base, expectedInformationGain: 99 })).toBeLessThanOrEqual(1);
    expect(computePriority({ ...base, previousFailurePenalty: 99 })).toBeGreaterThanOrEqual(0);
    const sum = Object.values(DEFAULT_PRIORITY_WEIGHTS).reduce((a, b) => a + b, 0);
    expect(sum).toBeGreaterThan(0.5);
    expect(sum).toBeLessThanOrEqual(1);
  });

  it('quota-adjusted ordering prefers cheap tasks when quota is pressured (§40)', () => {
    const taskA = { priority: 0.9, tokens: 500 };
    const taskB = { priority: 0.85, tokens: 1_500 };
    const taskC = { priority: 0.8, tokens: 5_000 };
    // Equal-ish priorities: token cost breaks the tie toward cheaper tasks.
    expect(quotaAdjustedPriority(taskA.priority, taskA.tokens)).toBeGreaterThan(
      quotaAdjustedPriority(taskB.priority, taskB.tokens),
    );
    expect(quotaAdjustedPriority(taskB.priority, taskB.tokens)).toBeGreaterThan(
      quotaAdjustedPriority(taskC.priority, taskC.tokens),
    );
    // A strongly higher priority still wins over cheap cost.
    expect(quotaAdjustedPriority(1, 5_000)).toBeGreaterThan(quotaAdjustedPriority(0.1, 100));
  });
});
