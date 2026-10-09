/**
 * Evidence strength classification (spec §69-§70).
 *
 * Explainable classification — never just a number. Levels follow §70:
 * WEAK / MODERATE / STRONG / CONFIRMATORY / CONTRADICTORY, with reasons.
 */
import type { EvidenceStrengthAssessment } from '@aegis/contracts';
import type { AuthorizationMatrixRecord, DifferentialResultRecord } from '@aegis/database';

export interface EvidenceContext {
  /** Reproduced observations of the same behavior (§72). */
  reproductionCount: number;
  /** Cross-identity comparison present (§99). */
  crossIdentityEvidence: boolean;
  /** Object-level matrix rows present (§98). */
  objectLevelEvidence: boolean;
  /** Baseline exists and differs (§100). */
  baselineDifferential: DifferentialResultRecord | null;
  /** Anonymous outcome available (public-object alternative, §47). */
  anonymousOutcome: string | null;
}

export function classifyEvidence(context: EvidenceContext): EvidenceStrengthAssessment {
  const reasons: string[] = [];
  let score = 0;

  if (context.reproductionCount >= 2) {
    score += 2;
    reasons.push(`behavior reproduced ${context.reproductionCount} times`);
  } else {
    reasons.push('single observation (not yet reproduced)');
  }
  if (context.crossIdentityEvidence) {
    score += 2;
    reasons.push('cross-identity comparison available');
  }
  if (context.objectLevelEvidence) {
    score += 1;
    reasons.push('object-level authorization evidence available');
  }
  if (context.baselineDifferential) {
    const changed = isMateriallyChanged(context.baselineDifferential);
    if (changed) {
      score += 2;
      reasons.push('baseline differs semantically from the candidate response');
    } else {
      reasons.push('baseline does NOT differ materially (weakens hypothesis)');
    }
  } else {
    reasons.push('no baseline differential recorded yet');
  }
  if (context.anonymousOutcome === 'ALLOWED') {
    reasons.push('anonymous access succeeds (supports public/shared interpretation)');
    return {
      level: 'CONTRADICTORY',
      reasons: [...reasons, 'the public-object alternative explains the behavior'],
    };
  }

  if (score >= 6) return { level: 'STRONG', reasons };
  if (score >= 4) return { level: 'MODERATE', reasons };
  return { level: 'WEAK', reasons };
}

/**
 * CONFIRMATORY: a verification explicitly reproduced the behavior with a
 * stable baseline (§70). Used by the verification engine only.
 */
export function confirmatory(reasons: string[]): EvidenceStrengthAssessment {
  return { level: 'CONFIRMATORY', reasons };
}

export function contradictory(reasons: string[]): EvidenceStrengthAssessment {
  return { level: 'CONTRADICTORY', reasons };
}

function isMateriallyChanged(differential: DifferentialResultRecord): boolean {
  const summary = (differential.summary ?? {}) as Record<string, unknown>;
  const statusChanged = Boolean(summary['status_changed']);
  const schemaChanged = Boolean(summary['schema_changed']);
  const fieldsRemoved = Array.isArray(summary['fields_removed']) ? (summary['fields_removed'] as string[]).length : 0;
  const fieldsAdded = Array.isArray(summary['fields_added']) ? (summary['fields_added'] as string[]).length : 0;
  const similarity = typeof summary['body_similarity'] === 'number' ? (summary['body_similarity'] as number) : 1;
  return statusChanged || schemaChanged || fieldsRemoved > 0 || fieldsAdded > 0 || similarity < 0.85;
}

/** Count reproductions of the same outcome per object (§72 reproducibility). */
export function reproductionCountFor(
  matrix: AuthorizationMatrixRecord[],
  endpointId: string,
  objectRef: string,
  outcome: string,
): number {
  return matrix.filter(
    (entry) => entry.endpoint_id === endpointId && entry.object_ref === objectRef && entry.outcome === outcome,
  ).length;
}
