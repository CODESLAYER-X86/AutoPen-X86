/**
 * Hypothesis prioritizer (spec Part 6 §17).
 *
 * priority =
 *     expected_information_gain
 *   × hypothesis_relevance
 *   × impact
 *   × novelty
 *   ÷ test_cost
 *
 * with penalties for: risk, duplicate_test, known_dead_end,
 * dependency_missing, rate_limit_pressure. Weights are configurable — the
 * exact mathematical formula is never hard-coded policy (§17).
 */
export interface PrioritizerWeights {
  informationGain: number;
  hypothesisRelevance: number;
  impact: number;
  novelty: number;
  costDivisor: number;
  penalties: {
    risk: number;
    duplicate: number;
    deadEnd: number;
    dependencyMissing: number;
    rateLimitPressure: number;
  };
}

export const DEFAULT_PRIORITIZER_WEIGHTS: PrioritizerWeights = {
  informationGain: 0.32,
  hypothesisRelevance: 0.22,
  impact: 0.18,
  novelty: 0.14,
  costDivisor: 0.14,
  penalties: {
    risk: 0.15,
    duplicate: 0.9, // duplicates are effectively killed
    deadEnd: 0.7,
    dependencyMissing: 0.4,
    rateLimitPressure: 0.1,
  },
};

export interface PrioritizationInput {
  expectedInformationGain: number;
  hypothesisRelevance: number;
  impact: number;
  novelty: number;
  testCost: number;
  risk: number;
  isDuplicate: boolean;
  hitsDeadEnd: boolean;
  dependencyMissing: boolean;
  rateLimitPressure: number;
}

export interface HypothesisPrioritizer {
  weights: PrioritizerWeights;
  score(input: PrioritizationInput): number;
}

export class WeightedHypothesisPrioritizer implements HypothesisPrioritizer {
  readonly weights: PrioritizerWeights;

  constructor(weights?: Partial<PrioritizerWeights> & { penalties?: Partial<PrioritizerWeights['penalties']> }) {
    this.weights = {
      ...DEFAULT_PRIORITIZER_WEIGHTS,
      ...weights,
      penalties: { ...DEFAULT_PRIORITIZER_WEIGHTS.penalties, ...weights?.penalties },
    };
  }

  score(input: PrioritizationInput): number {
    const w = this.weights;
    // Multiplicative core (§17), guarded against zero cost. The weighted
    // value is bounded BEFORE penalties so that penalties always reduce the
    // final score proportionally (duplicates can never survive, §17).
    const cost = Math.max(0.05, input.testCost);
    const value = clamp01(
      clamp01(input.expectedInformationGain) * w.informationGain +
        clamp01(input.hypothesisRelevance) * w.hypothesisRelevance +
        clamp01(input.impact) * w.impact +
        clamp01(input.novelty) * w.novelty,
    );
    const core = clamp01(value / (cost * (1 + w.costDivisor)) + value * 0.5);

    let penalty = 1;
    penalty *= 1 - clamp01(input.risk) * w.penalties.risk;
    if (input.isDuplicate) penalty *= 1 - w.penalties.duplicate;
    if (input.hitsDeadEnd) penalty *= 1 - w.penalties.deadEnd;
    if (input.dependencyMissing) penalty *= 1 - w.penalties.dependencyMissing;
    penalty *= 1 - clamp01(input.rateLimitPressure) * w.penalties.rateLimitPressure;
    penalty = Math.max(0, penalty);

    return clamp01(core * penalty);
  }
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}
