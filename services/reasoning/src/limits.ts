/**
 * Reasoning engine resource limits (spec §113).
 *
 * Protects against pathological targets: bounded graph growth, bounded
 * observation-derived state, bounded comparison sizes. Enforced by the
 * processor; violations are recorded, never crash the engagement (§112).
 */
export interface ReasoningLimits {
  maxGraphNodes: number;
  maxGraphEdges: number;
  maxSignals: number;
  maxParameters: number;
  maxEndpoints: number;
  maxObjects: number;
  /** Bounded example values per parameter (§114). */
  maxExampleValues: number;
  /** Max bytes of preview text compared differentially (§114). */
  maxComparisonBytes: number;
  maxMutationCandidates: number;
}

export const DEFAULT_REASONING_LIMITS: ReasoningLimits = {
  maxGraphNodes: 5000,
  maxGraphEdges: 20000,
  maxSignals: 5000,
  maxParameters: 10000,
  maxEndpoints: 5000,
  maxObjects: 2000,
  maxExampleValues: 8,
  maxComparisonBytes: 65_536,
  maxMutationCandidates: 64,
};

export class ReasoningLimitError extends Error {
  constructor(
    public readonly limit: keyof ReasoningLimits,
    public readonly current: number,
  ) {
    super(`Reasoning resource limit reached: ${limit} (${current})`);
    this.name = 'ReasoningLimitError';
  }
}
