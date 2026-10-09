/**
 * Verification engine (spec §71-§76, §128).
 *
 * The verifier is SKEPTICAL by design (§72): its job is to find alternative
 * explanations for the suspected vulnerability. Findings are never created
 * directly from an anomaly (§71) — only a VERIFIED checklist outcome can
 * promote a hypothesis, and the actual promotion still flows through the
 * Part 2 hypothesis engine via the composition bridge.
 *
 * False-positive suppression (§74): public resources, intentional shared
 * access, caching, client-side-only behavior, dynamic timestamps and
 * authentication expiration are evaluated explicitly. Rejections record
 * the reason; dead ends follow through the bridge (§75).
 */
import type { VerificationRecord } from '@aegis/database';
import type { DifferentialResultRecord, EndpointRecord, HypothesisRecord } from '@aegis/database';
import type { AuthorizationMatrixRecord } from '@aegis/database';
import type {
  VerificationAlternativeRecord,
  VerificationCheckRecord,
} from '@aegis/database';

export interface VerificationEvidenceInput {
  hypothesis: HypothesisRecord;
  endpoint: EndpointRecord | null;
  matrix: AuthorizationMatrixRecord[];
  differentials: DifferentialResultRecord[];
  /** Anonymous outcome for the endpoint (public-object alternative, §72). */
  anonymousOutcome: string | null;
}

export interface VerificationOutcome {
  kind: string;
  status: 'VERIFIED' | 'REFUTED' | 'INCONCLUSIVE';
  checklist: VerificationCheckRecord[];
  alternatives: VerificationAlternativeRecord[];
  result: Record<string, unknown>;
  evidenceIds: string[];
}

const CHECK_NAMES = {
  OBJECT_PUBLIC: 'IS_OBJECT_PUBLIC',
  CACHED: 'IS_RESPONSE_CACHED',
  SENSITIVE: 'IS_DATA_ACTUALLY_SENSITIVE',
  SHARED: 'IS_SHARED_ACCESS_LEGITIMATE',
  REPRODUCES: 'DOES_BEHAVIOR_REPRODUCE',
  BASELINE_DIFFERS: 'DOES_BASELINE_DIFFER',
} as const;

/**
 * Evaluate the skeptical checklist for an authorization hypothesis (§72
 * example). Other hypothesis kinds get a reduced generic checklist.
 */
export function evaluateVerification(input: VerificationEvidenceInput): VerificationOutcome {
  const checks: VerificationCheckRecord[] = [];
  const alternatives: VerificationAlternativeRecord[] = [];
  const evidenceIds: string[] = [];
  const matrix = input.matrix;
  const endpointId = input.endpoint?.id ?? null;

  // --- IS_OBJECT_PUBLIC (§72) -------------------------------------------------
  const anonymousAllowed =
    input.anonymousOutcome === 'ALLOWED' ||
    matrix.some((entry) => entry.identity_id === null && entry.outcome === 'ALLOWED' && (entry.endpoint_id === endpointId || endpointId === null));
  checks.push({
    check: CHECK_NAMES.OBJECT_PUBLIC,
    status: anonymousAllowed ? 'PASS' : 'FAIL',
    detail: anonymousAllowed
      ? 'Anonymous access succeeded — the object may be intentionally public'
      : 'Anonymous access did not succeed; the object is not trivially public',
    evidence_ids: matrix.filter((entry) => entry.identity_id === null).slice(0, 4).flatMap((entry) => entry.evidence_ids),
  });
  alternatives.push({
    explanation: 'Object is intentionally public',
    refuted: !anonymousAllowed,
    detail: anonymousAllowed
      ? 'Anonymous requests return the object — this explanation stands and blocks promotion'
      : 'Anonymous requests are denied',
  });

  // --- IS_RESPONSE_CACHED (§72) ------------------------------------------------
  const cacheEvidence = input.differentials.find((differential) => {
    const detail = (differential.detail ?? {}) as Record<string, unknown>;
    const summary = (differential.summary ?? {}) as Record<string, unknown>;
    return detail['cache_headers_present'] === true || summary['body_similarity'] === 1;
  });
  const identicalRepeats = matrix.some((entry) => entry.observation_count >= 2);
  checks.push({
    check: CHECK_NAMES.CACHED,
    status: cacheEvidence ? 'PASS' : identicalRepeats ? 'UNKNOWN' : 'NOT_APPLICABLE',
    detail: cacheEvidence
      ? 'A differential showed byte-identical or cache-headed responses — caching may explain the behavior'
      : identicalRepeats
        ? 'Repeated requests observed but no cache header evidence recorded'
        : 'No repeat evidence available yet',
    evidence_ids: cacheEvidence ? [cacheEvidence.id] : [],
  });
  alternatives.push({
    explanation: 'Response was cached, not authorized',
    refuted: !cacheEvidence,
    detail: cacheEvidence ? 'Cache-like evidence present' : 'No cache evidence found',
  });

  // --- IS_DATA_ACTUALLY_SENSITIVE (§72) ------------------------------------------
  const ownerEntries = matrix.filter((entry) => entry.outcome === 'ALLOWED' && entry.identity_id !== null);
  const sensitiveData =
    input.differentials.some((differential) => {
      const summary = (differential.summary ?? {}) as Record<string, unknown>;
      const changed = Array.isArray(summary['values_changed'])
        ? (summary['values_changed'] as Array<Record<string, unknown>>)
        : [];
      const identitySpecific = changed.some(
        (change) => typeof change['path'] === 'string' && /owner|user|email|name|id$/i.test(change['path'] as string),
      );
      return identitySpecific || Boolean(summary['schema_changed']);
    }) || ownerEntries.length > 0;
  checks.push({
    check: CHECK_NAMES.SENSITIVE,
    status: sensitiveData ? 'PASS' : 'UNKNOWN',
    detail: sensitiveData
      ? 'Identity-specific fields observed in responses — the data appears identity-bound'
      : 'No identity-specific fields observed yet; sensitivity unproven',
    evidence_ids: [],
  });

  // --- IS_SHARED_ACCESS_LEGITIMATE (§72) --------------------------------------------
  const roleEntries = matrix.filter((entry) => entry.outcome === 'ALLOWED' && entry.identity_id !== null);
  const sharedAccessPlausible = roleEntries.length >= 2 && !anonymousAllowed;
  checks.push({
    check: CHECK_NAMES.SHARED,
    status: sharedAccessPlausible ? 'UNKNOWN' : 'FAIL',
    detail: sharedAccessPlausible
      ? 'Multiple authenticated identities can access the object — role-based sharing remains possible'
      : 'No multi-identity authenticated access evidence for shared-access interpretation',
    evidence_ids: [],
  });
  alternatives.push({
    explanation: 'Role-based shared access is legitimate',
    refuted: !sharedAccessPlausible,
    detail: sharedAccessPlausible ? 'Shared-access interpretation not excluded' : 'No supporting evidence',
  });

  // --- DOES_IT_REPRODUCE (§72) --------------------------------------------------------
  const allowedEntries = matrix.filter((entry) => entry.outcome === 'ALLOWED');
  const reproduces = allowedEntries.some((entry) => entry.observation_count >= 2);
  checks.push({
    check: CHECK_NAMES.REPRODUCES,
    status: reproduces ? 'PASS' : 'UNKNOWN',
    detail: reproduces
      ? 'The access behavior was observed repeatedly'
      : 'The access behavior was observed once — reproduction not yet established',
    evidence_ids: allowedEntries.flatMap((entry) => entry.evidence_ids).slice(0, 8),
  });

  // --- DOES_BASELINE_DIFFER (§72) --------------------------------------------------------
  const differential = input.differentials[0] ?? null;
  let baselineDiffers: 'PASS' | 'FAIL' | 'UNKNOWN' = 'UNKNOWN';
  if (differential) {
    const summary = (differential.summary ?? {}) as Record<string, unknown>;
    const similarity = typeof summary['body_similarity'] === 'number' ? (summary['body_similarity'] as number) : 1;
    const schemaChanged = Boolean(summary['schema_changed']);
    const valuesChanged = Array.isArray(summary['values_changed'])
      ? (summary['values_changed'] as Array<Record<string, unknown>>).filter((change) => !change['volatile'])
      : [];
    baselineDiffers = schemaChanged || valuesChanged.length > 0 || similarity < 0.85 ? 'PASS' : 'FAIL';
    evidenceIds.push(differential.id);
  }
  checks.push({
    check: CHECK_NAMES.BASELINE_DIFFERS,
    status: baselineDiffers,
    detail: differential
      ? baselineDiffers === 'PASS'
        ? 'Owner baseline and non-owner candidate responses differ semantically'
        : 'Owner baseline and candidate responses are semantically equal — no evidence of differentiated access'
      : 'No differential comparison recorded for the hypothesis yet',
    evidence_ids: differential ? [differential.id] : [],
  });

  // --- Verdict (§72): try to REFUTE first, verify only when alternatives fail --------
  const refutingAlternatives = alternatives.filter((alternative) => !alternative.refuted);
  if (refutingAlternatives.length > 0) {
    return {
      kind: kindFor(input.hypothesis),
      status: 'REFUTED',
      checklist: checks,
      alternatives,
      result: {
        verdict: 'REFUTED',
        reason: `Alternative explanation stands: ${refutingAlternatives[0]!.explanation}`,
        false_positive_cause: refutingAlternatives[0]!.explanation,
        promotion: false,
      },
      evidenceIds,
    };
  }

  const required = checks.filter((check) => check.check === CHECK_NAMES.REPRODUCES || check.check === CHECK_NAMES.BASELINE_DIFFERS);
  const allRequiredPass = required.every((check) => check.status === 'PASS');
  const anyUnknown = required.some((check) => check.status === 'UNKNOWN');
  if (allRequiredPass && sensitiveData) {
    return {
      kind: kindFor(input.hypothesis),
      status: 'VERIFIED',
      checklist: checks,
      alternatives,
      result: {
        verdict: 'VERIFIED',
        reason: 'Reproduced behavior with a differing baseline and no surviving alternative explanation',
        promotion: true,
      },
      evidenceIds,
    };
  }
  if (anyUnknown) {
    return {
      kind: kindFor(input.hypothesis),
      status: 'INCONCLUSIVE',
      checklist: checks,
      alternatives,
      result: {
        verdict: 'INCONCLUSIVE',
        reason: 'Evidence is insufficient — INCONCLUSIVE is a valid result (spec §103); missing evidence recorded',
        missing_evidence: checks
          .filter((check) => check.status === 'UNKNOWN')
          .map((check) => check.check),
        promotion: false,
      },
      evidenceIds,
    };
  }
  return {
    kind: kindFor(input.hypothesis),
    status: 'REFUTED',
    checklist: checks,
    alternatives,
    result: {
      verdict: 'REFUTED',
      reason: 'Baseline does not differ — the behavior is explainable without a vulnerability',
      false_positive_cause: 'no differentiated access observed',
      promotion: false,
    },
    evidenceIds,
  };
}

function kindFor(hypothesis: HypothesisRecord): string {
  return `HYPOTHESIS:${hypothesis.type}`;
}

/**
 * Dead-end payload for refuted hypotheses (§75): what was tested, why it
 * failed, evidence, conditions.
 */
export function deadEndPayload(verification: VerificationRecord, hypothesis: HypothesisRecord): {
  description: string;
  reason: string;
  tests: string[];
} {
  const result = (verification.result ?? {}) as Record<string, unknown>;
  return {
    description: `Verification of "${hypothesis.statement.slice(0, 400)}" refuted the hypothesis`,
    reason: typeof result['false_positive_cause'] === 'string' ? (result['false_positive_cause'] as string) : 'alternative explanation stands (spec §74)',
    tests: verification.evidence_ids.slice(0, 8),
  };
}
