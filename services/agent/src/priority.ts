/**
 * Task priority scoring (spec Part 2 §20-§21).
 *
 * Deterministic weighted factors — severity alone is explicitly NOT the
 * driver (§20): a low-severity observation that unlocks the whole attack
 * surface can deserve the highest priority. All factors are 0..1; the
 * composite is clamped to 0..1. The weighting is replaceable via the
 * options object (spec §25's "keep the scoring function replaceable"
 * principle, applied to priorities).
 */

export interface PriorityFactors {
  /** Confidence of the hypothesis under test (0..1). */
  hypothesisConfidence: number;
  /** Leader-estimated potential impact (0..1). */
  potentialImpact: number;
  /** Expected information gain — how much this distinguishes hypotheses (§21). */
  expectedInformationGain: number;
  /** Estimated test cost (0..1; 1 = very expensive). Lowers priority. */
  testCost: number;
  /** Scope relevance (0..1; must be 1 for in-scope work, enforced upstream). */
  scopeRelevance: number;
  /** Novelty (0..1; repeated tests score lower — anti-loop input). */
  novelty: number;
  /** Dependency readiness (0..1; blocked tasks score lower). */
  dependencyReadiness: number;
  /** Previous failure penalty (0..1; grows with failed attempts). */
  previousFailurePenalty: number;
}

export const DEFAULT_PRIORITY_WEIGHTS = {
  hypothesisConfidence: 0.18,
  potentialImpact: 0.16,
  expectedInformationGain: 0.3,
  testCost: 0.06,
  scopeRelevance: 0.14,
  novelty: 0.08,
  dependencyReadiness: 0.05,
  previousFailurePenalty: 0.03,
} as const;

export type PriorityWeights = Readonly<Record<keyof PriorityFactors, number>>;

const clamp01 = (value: number): number => Math.min(1, Math.max(0, value));

export function computePriority(
  factors: PriorityFactors,
  weights: PriorityWeights = DEFAULT_PRIORITY_WEIGHTS,
): number {
  const f: PriorityFactors = {
    hypothesisConfidence: clamp01(factors.hypothesisConfidence),
    potentialImpact: clamp01(factors.potentialImpact),
    expectedInformationGain: clamp01(factors.expectedInformationGain),
    // Cost, novelty, failure and readiness are "negative" factors: higher
    // value means worse; convert to benefit (1 - x).
    testCost: clamp01(factors.testCost),
    scopeRelevance: clamp01(factors.scopeRelevance),
    novelty: clamp01(factors.novelty),
    dependencyReadiness: clamp01(factors.dependencyReadiness),
    previousFailurePenalty: clamp01(factors.previousFailurePenalty),
  };

  const benefit =
    weights.hypothesisConfidence * f.hypothesisConfidence +
    weights.potentialImpact * f.potentialImpact +
    weights.expectedInformationGain * f.expectedInformationGain +
    weights.scopeRelevance * f.scopeRelevance +
    weights.novelty * f.novelty +
    weights.dependencyReadiness * f.dependencyReadiness;

  const penalty =
    weights.testCost * f.testCost + weights.previousFailurePenalty * f.previousFailurePenalty;

  return clamp01(benefit - penalty);
}

/**
 * Quota-aware tie-breaking (spec Part 2 §40): when remaining TPM is low,
 * prefer cheaper tasks. Returns an adjusted ordering score where small tasks
 * gain a relative boost.
 */
export function quotaAdjustedPriority(priority: number, estimatedTokens: number): number {
  return priority - estimatedTokens / 1_000_000;
}
