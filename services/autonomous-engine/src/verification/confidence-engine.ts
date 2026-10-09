/**
 * Confidence engine (spec Part 6 §28).
 *
 * A finding's confidence is computed from named dimensions —
 * direct_evidence, reproducibility, identity_differential,
 * control_comparison, source_confirmation, alternative_explanations,
 * consistency, impact_evidence — and is NEVER severity. Output: a numeric
 * confidence, a HIGH/MEDIUM/LOW level and human-readable reasons.
 */
export interface ConfidenceInput {
  reproduced: boolean;
  identityDifferential: boolean;
  controlComparison: boolean;
  alternativesRuledOut: boolean;
  directEvidenceCount: number;
  consistentObservations: number;
}

export interface ConfidenceAssessment {
  confidence: number;
  level: 'HIGH' | 'MEDIUM' | 'LOW';
  reasons: string[];
  dimensions: Record<string, number>;
}

const WEIGHTS = {
  directEvidence: 0.15,
  reproducibility: 0.2,
  identityDifferential: 0.2,
  controlComparison: 0.2,
  alternatives: 0.15,
  consistency: 0.1,
};

export class ConfidenceEngine {
  assess(input: ConfidenceInput): ConfidenceAssessment {
    const reasons: string[] = [];

    const directEvidence = Math.min(1, input.directEvidenceCount / 3);
    if (directEvidence >= 0.67) reasons.push(`${input.directEvidenceCount} pieces of direct evidence linked`);

    const reproducibility = input.reproduced ? 1 : 0.2;
    if (input.reproduced) reasons.push('Behavior reproduced with independent requests');
    else reasons.push('Not yet reproduced independently');

    const identityDifferential = input.identityDifferential ? 1 : 0.3;
    if (input.identityDifferential) reasons.push('Identity differential confirmed');

    const controlComparison = input.controlComparison ? 1 : 0.3;
    if (input.controlComparison) reasons.push('Expected control behavior established');
    else reasons.push('Control comparison missing');

    const alternatives = input.alternativesRuledOut ? 1 : 0.25;
    if (input.alternativesRuledOut) reasons.push('All alternative explanations ruled out');

    const consistency = Math.min(1, 0.5 + input.consistentObservations * 0.25);

    const confidence =
      WEIGHTS.directEvidence * directEvidence +
      WEIGHTS.reproducibility * reproducibility +
      WEIGHTS.identityDifferential * identityDifferential +
      WEIGHTS.controlComparison * controlComparison +
      WEIGHTS.alternatives * alternatives +
      WEIGHTS.consistency * consistency;

    const bounded = Math.max(0, Math.min(1, confidence));
    const level = bounded >= 0.75 ? 'HIGH' : bounded >= 0.45 ? 'MEDIUM' : 'LOW';

    return {
      confidence: Number(bounded.toFixed(3)),
      level,
      reasons: reasons.slice(0, 8),
      dimensions: {
        direct_evidence: directEvidence,
        reproducibility,
        identity_differential: identityDifferential,
        control_comparison: controlComparison,
        alternative_explanations: alternatives,
        consistency,
      },
    };
  }
}
