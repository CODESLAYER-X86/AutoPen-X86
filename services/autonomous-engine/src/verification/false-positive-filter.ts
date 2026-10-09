/**
 * False-positive filter (spec Part 6 §27).
 *
 * Before a candidate finding is confirmed:
 *
 *   Candidate -> Evidence sufficiency -> Alternative explanation check ->
 *   Reproduction -> Impact confirmation -> Confidence -> Confirmed/Rejected
 *
 * An HTTP 500 must never automatically become "SQL injection": the filter
 * actively tries to distinguish invalid state, server bug, malformed input,
 * authorization error, dependency failure and actual injection.
 */
import type { Repositories, TaskRecord, TestRecord } from '@aegis/database';

export interface FalsePositiveCheck {
  pass: boolean;
  reason: string;
}

export interface FalsePositiveFilterDeps {
  repos: Repositories;
}

export class FalsePositiveFilter {
  constructor(private readonly deps: FalsePositiveFilterDeps) {}

  /**
   * Evidence sufficiency check (§27): a candidate finding needs at least
   * direct evidence AND one comparison signal (differential or control).
   */
  async evidenceSufficiency(engagementId: string, hypothesisId: string): Promise<FalsePositiveCheck> {
    const links = await this.deps.repos.hypotheses.linksByHypothesis(hypothesisId);
    const evidence = links.filter((l) => l.ref_type === 'EVIDENCE').length;
    const tests = links.filter((l) => l.ref_type === 'TEST').length;
    if (evidence === 0) {
      return { pass: false, reason: 'no direct evidence linked to the hypothesis' };
    }
    if (tests === 0) {
      return { pass: false, reason: 'no executed test linked — an untested theory cannot be a finding' };
    }
    return { pass: true, reason: `${evidence} evidence refs and ${tests} test refs linked` };
  }

  /**
   * Alternative explanation check (§27): for error-shaped observations,
   * distinguish server bugs / malformed input / authorization errors from
   * actual injection before a finding is confirmed.
   */
  alternativeExplanations(input: {
    status: number;
    errorSignature: string | null;
    responseSemanticsChanged: boolean;
    inputReflected: boolean;
  }): string[] {
    const alternatives: string[] = [];
    if (input.status >= 500) {
      alternatives.push('server-side exception (bug, not a security boundary failure)');
      alternatives.push('dependency failure behind the endpoint');
    }
    if (input.status === 400 || input.status === 422) {
      alternatives.push('malformed input rejected by validation (correct behavior)');
    }
    if (input.status === 401 || input.status === 403) {
      alternatives.push('authorization error (correct control behavior)');
    }
    if (!input.responseSemanticsChanged) {
      alternatives.push('response semantics unchanged — observation may be environmental noise');
    }
    if (!input.inputReflected && input.errorSignature?.includes('SQL')) {
      alternatives.push('generic database error disclosure without demonstrated injection');
    }
    return alternatives;
  }

  /**
   * Duplicate-observation check: the same fingerprint observed before does
   * not add evidence (§27 consistency requires INDEPENDENT observations).
   */
  independentObservations(tests: TestRecord[]): number {
    const fingerprints = new Set(tests.map((t) => t.fingerprint));
    const completed = tests.filter((t) => t.status === 'COMPLETED');
    return Math.min(fingerprints.size, completed.length);
  }

  /** §61: reward discriminating tests, not request volume. */
  discriminates(tests: TestRecord[], task: TaskRecord | null): boolean {
    if (task === null) return false;
    const mutating = tests.some(
      (t) => t.hypothesis_id === task.hypothesis_id && t.result && t.result !== 'INCONCLUSIVE',
    );
    return mutating;
  }
}
