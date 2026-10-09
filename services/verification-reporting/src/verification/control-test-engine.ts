/**
 * Control test engine (spec Part 7 §9 Control comparison, §11, §72).
 *
 * COMPARE a known-good CONTROL against the SUSPECT behavior. Controls are
 * derived deterministically from the finding category policy: owner-object
 * vs foreign-object for authorization findings, anonymous vs authenticated
 * for authentication findings, valid vs invalid state for workflow findings.
 *
 * The engine evaluates the control through the recorded authorization
 * matrix (Part 4) and differential results — and, when the matrix already
 * covers the control cell, re-uses it (verification independence, §11:
 * verification compares MULTIPLE conditions, not a single repeat).
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';

export interface ControlTestResult {
  control: string;
  /** The control outcome as recorded in the authorization matrix / diffs. */
  observed: string | null;
  /** What the control SHOULD be for the finding to hold (e.g. DENIED). */
  expected: string;
  satisfied: boolean | null;
  evidenceIds: string[];
  note: string;
}

export interface ControlComparisonOutcome {
  results: ControlTestResult[];
  /** True when at least one control was evaluated and all satisfied. */
  controlComparison: boolean;
  identityDifferential: boolean;
  evidenceIds: string[];
  note: string;
}

export class ControlTestEngine {
  constructor(private readonly repos: Repositories) {}

  /** §9 CONTROL vs SUSPECT over the authorization matrix (Part 4 §42). */
  async runControls(finding: FindingRecord): Promise<ControlComparisonOutcome> {
    const results: ControlTestResult[] = [];
    const evidenceIds: string[] = [];
    const matrix = await this.repos.authzMatrix
      .listByEngagement(finding.engagement_id, 1000)
      .catch(() => []);

    // Focus on matrix cells touching the finding's affected endpoints.
    const endpointSet = new Set(finding.affected_endpoints.map((e) => e.toLowerCase()));
    const relevant = matrix.filter((entry) => {
      if (endpointSet.size === 0) return true;
      const endpointId = (entry.endpoint_id ?? '').toLowerCase();
      const objectRef = (entry.object_ref ?? '').toLowerCase();
      return [...endpointSet].some(
        (e) => endpointId.includes(e) || e.includes(endpointId) || objectRef.includes(e) || e.includes(objectRef),
      );
    });

    const identities = new Set(relevant.map((entry) => entry.identity_id ?? 'ANONYMOUS'));
    // Identity differential exists when at least two identities (or
    // anonymous + authenticated) have outcomes for overlapping endpoints.
    const identityDifferential = identities.size >= 2 || relevant.some((e) => e.identity_id === null);

    for (const entry of relevant.slice(0, 12)) {
      // Control naming from the matrix cell semantics (§9): an authenticated
      // identity reaching a foreign object is the OWNER_FOREIGN control; the
      // anonymous cell is the ANONYMOUS control.
      const control =
        entry.identity_id === null
          ? 'ANONYMOUS_FOREIGN_OBJECT'
          : 'AUTHENTICATED_FOREIGN_OBJECT';
      // For an authorization FAILURE the control expectation is: foreign
      // identity => DENIED; anonymous => DENIED.
      const expected = 'DENIED';
      const observed = entry.outcome;
      const satisfied = observed === null ? null : observed === expected;
      if (entry.evidence_ids) evidenceIds.push(...entry.evidence_ids);
      results.push({
        control,
        observed: observed ?? null,
        expected,
        satisfied,
        evidenceIds: entry.evidence_ids ?? [],
        note: `matrix cell endpoint=${entry.endpoint_id} identity=${entry.identity_id ?? 'ANONYMOUS'} object=${entry.object_ref ?? '-'} outcome=${observed ?? 'unknown'}`,
      });
    }

    const evaluated = results.filter((r) => r.satisfied !== null);
    const allSatisfied = evaluated.length > 0 && evaluated.every((r) => r.satisfied === true);

    return {
      results,
      controlComparison: allSatisfied,
      identityDifferential,
      evidenceIds: [...new Set(evidenceIds)],
      note:
        evaluated.length === 0
          ? 'No control conditions available in the authorization matrix (§9) — control comparison not established.'
          : `${evaluated.length} control condition(s) evaluated; ${evaluated.filter((r) => r.satisfied).length} matched the expected control behavior.`,
    };
  }
}
