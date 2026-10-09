/**
 * Confidence engine (spec Part 7 §15-§16).
 *
 * Confidence is a DETERMINISTIC weighted score over named dimensions —
 * never a random LLM number, and NEVER severity (§16): a potentially
 * critical issue with weak evidence must remain uncertain. Weights and
 * thresholds are configurable.
 */
export interface ConfidenceInput {
  evidenceCount: number;
  reproduced: boolean;
  reproductionConsistent: boolean;
  controlComparison: boolean;
  identityDifferential: boolean;
  alternativesEliminated: boolean;
  contradictoryEvidencePresent: boolean;
}

export interface ConfidenceAssessmentResult {
  confidence: number;
  level: 'HIGH' | 'MEDIUM' | 'LOW';
  dimensions: Record<string, number>;
  reasons: string[];
}

const DEFAULT_WEIGHTS: Record<string, number> = {
  direct_evidence: 0.15,
  reproducibility: 0.2,
  control_comparison: 0.2,
  identity_differential: 0.1,
  alternative_explanations: 0.2,
  consistency: 0.15,
};

const DEFAULT_THRESHOLDS = { high: 0.75, medium: 0.45 };

/** Contradictory evidence: §82 — confidence must DECREASE, not be ignored. */
const CONTRADICTION_PENALTY = 0.25;

export class ConfidenceEngine {
  private readonly weights: Record<string, number>;
  private readonly thresholds: { high: number; medium: number };

  constructor(
    weights?: Record<string, number>,
    thresholds?: { high: number; medium: number },
  ) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
    this.thresholds = thresholds ?? DEFAULT_THRESHOLDS;
  }

  assess(input: ConfidenceInput): ConfidenceAssessmentResult {
    const reasons: string[] = [];

    const directEvidence = Math.min(1, input.evidenceCount / 3);
    if (input.evidenceCount >= 3) reasons.push(`${input.evidenceCount} pieces of linked evidence`);

    const reproducibility = input.reproduced ? (input.reproductionConsistent ? 1 : 0.5) : 0.2;
    if (input.reproduced && input.reproductionConsistent) {
      reasons.push('Behavior reproduced independently and consistently');
    } else if (input.reproduced) {
      reasons.push('Reproduced but the repeated behavior differed from the original');
    } else {
      reasons.push('Not independently reproduced');
    }

    const controlComparison = input.controlComparison ? 1 : 0.3;
    if (input.controlComparison) reasons.push('Expected control behavior established');
    else reasons.push('Control comparison missing');

    const identityDifferential = input.identityDifferential ? 1 : 0.3;
    if (input.identityDifferential) reasons.push('Identity differential present');

    const alternatives = input.alternativesEliminated ? 1 : 0.25;
    if (input.alternativesEliminated) reasons.push('All alternative explanations eliminated');
    else reasons.push('Alternative explanations survive');

    const consistency = input.contradictoryEvidencePresent ? 0.3 : 0.9;
    if (input.contradictoryEvidencePresent) {
      reasons.push('Contradictory evidence present — confidence reduced (§82)');
    }

    const w = (name: string): number => this.weights[name] ?? 0;
    let confidence =
      w('direct_evidence') * directEvidence +
      w('reproducibility') * reproducibility +
      w('control_comparison') * controlComparison +
      w('identity_differential') * identityDifferential +
      w('alternative_explanations') * alternatives +
      w('consistency') * consistency;

    if (input.contradictoryEvidencePresent) {
      confidence -= CONTRADICTION_PENALTY;
    }

    const bounded = Math.max(0, Math.min(1, confidence));
    const level: ConfidenceAssessmentResult['level'] =
      bounded >= this.thresholds.high ? 'HIGH' : bounded >= this.thresholds.medium ? 'MEDIUM' : 'LOW';

    return {
      confidence: Number(bounded.toFixed(3)),
      level,
      dimensions: {
        direct_evidence: directEvidence,
        reproducibility,
        control_comparison: controlComparison,
        identity_differential: identityDifferential,
        alternative_explanations: alternatives,
        consistency,
      },
      reasons: reasons.slice(0, 10),
    };
  }
}
