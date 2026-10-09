/**
 * Verification planner (spec Part 7 §7-§9, §11).
 *
 * For each candidate finding, generate a deterministic verification plan:
 * chosen strategies (§9), control conditions, expected result, required
 * evidence (§8) and an evidence-sufficiency gate (§7) evaluated against what
 * actually exists. Verification that would be a literal repeat of discovery
 * is rejected (§11: verification must be meaningfully different).
 */
import type { Repositories } from '@aegis/database';
import type { FindingRecord } from '@aegis/database';
import { resolvePolicy, type VerificationPolicyRule } from './verification-policy.js';
import type { VerificationStrategy } from './verification-policy.js';

export interface PlannedVerification {
  strategies: VerificationStrategy[];
  controls: string[];
  expectedResult: Record<string, unknown>;
  requiredEvidence: Array<{ kind: string; description: string; required: boolean }>;
  sufficiency: {
    sufficient: boolean;
    missing: string[];
    dimensions: Record<string, boolean>;
    note: string;
  };
  policy: VerificationPolicyRule;
}

const STRATEGY_ORDER: Record<string, number> = {
  IDENTITY_DIFFERENTIAL: 1,
  AUTHENTICATION_DIFFERENTIAL: 1,
  STATE_DIFFERENTIAL: 1,
  CONTROL_COMPARISON: 2,
  REPRODUCTION: 3,
  SOURCE_CONFIRMATION: 4,
  EVIDENCE_REVIEW: 5,
};

export class VerificationPlanner {
  constructor(private readonly repos: Repositories) {}

  /** §8: plan for one candidate finding. */
  async plan(
    finding: FindingRecord,
    overrides?: { strategies?: VerificationStrategy[] },
  ): Promise<PlannedVerification> {
    const policy = resolvePolicy(finding.category, finding.severity);
    // §11: verification must differ from discovery. If the planner cannot
    // offer at least one non-reproduction comparison, the plan is widened
    // with EVIDENCE_REVIEW so the verifier examines what is actually proven.
    const strategies = (overrides?.strategies?.length ? overrides.strategies : policy.strategies)
      .slice()
      .sort((a, b) => (STRATEGY_ORDER[a] ?? 9) - (STRATEGY_ORDER[b] ?? 9));
    if (!strategies.some((s) => s !== 'REPRODUCTION')) {
      strategies.push('EVIDENCE_REVIEW');
    }

    const sufficiency = await this.evaluateSufficiency(finding);

    return {
      strategies,
      controls: policy.controls,
      expectedResult: {
        control_behavior: 'DENIED',
        suspect_behavior: finding.expected_behavior ? 'ALLOWED' : 'ANOMALOUS',
        policy_gaps: policy.categories.length > 0 ? policy.categories : ['DEFAULT'],
      },
      requiredEvidence: [
        { kind: 'REQUEST', description: 'The request that produced the suspect behavior', required: true },
        { kind: 'RESPONSE', description: 'The response observed for the suspect behavior', required: true },
        { kind: 'CONTROL_RESPONSE', description: 'Response for the control condition', required: policy.requireControlComparison },
        {
          kind: 'IDENTITY_ID',
          description: 'Identity used for the suspect request',
          required: policy.requireIdentityDifferential,
        },
        {
          kind: 'REPRODUCTION_RESULT',
          description: 'Result of an independent reproduction attempt',
          required: policy.requireReproduction,
        },
      ],
      sufficiency,
      policy,
    };
  }

  /**
   * §7: evidence sufficiency. Required dimensions: observed behavior,
   * affected target, test identity, request/action, response/result,
   * baseline/control, reproducibility. Missing control conditions make the
   * observation ambiguous -> insufficient.
   */
  async evaluateSufficiency(
    finding: FindingRecord,
  ): Promise<PlannedVerification['sufficiency']> {
    const dimensions: Record<string, boolean> = {
      observed_behavior: Boolean(finding.observed_behavior ?? finding.description),
      affected_target: finding.target_refs.length > 0 || finding.affected_endpoints.length > 0,
      test_identity: finding.affected_identities.length > 0,
      request: false,
      response: false,
      baseline_control: false,
      reproducibility: false,
    };

    // Look for concrete request/response records among the linked evidence.
    const evidenceIds = finding.evidence_ids;
    for (const evidenceId of evidenceIds) {
      const record = await this.repos.evidence.findById(evidenceId).catch(() => null);
      if (!record) continue;
      if (record.type.includes('REQUEST')) dimensions.request = true;
      if (record.type.includes('RESPONSE')) dimensions.response = true;
    }
    // Differential results linked through the hypothesis act as controls.
    if (finding.hypothesis_id) {
      const differentials = await this.repos.differentialResults
        .listByHypothesis(finding.hypothesis_id)
        .catch(() => []);
      if (differentials.length > 0) {
        dimensions.baseline_control = differentials.some((d) => d.summary && typeof d.summary === 'object');
      }
    }
    // Existing verification results prove reproducibility attempts.
    const results = await this.repos.verificationResults
      .listByFinding(finding.engagement_id, finding.id)
      .catch(() => []);
    if (results.some((r) => r.reproduced)) {
      dimensions.reproducibility = true;
    }

    const missing: string[] = [];
    if (!dimensions.observed_behavior) missing.push('observed behavior');
    if (!dimensions.affected_target) missing.push('affected target');
    if (!dimensions.request) missing.push('request record');
    if (!dimensions.response) missing.push('response record');
    if (!dimensions.baseline_control) missing.push('baseline/control comparison');
    if (!dimensions.reproducibility) missing.push('reproducibility evidence');

    return {
      sufficient: missing.length === 0,
      missing,
      dimensions,
      note:
        missing.length === 0
          ? 'All evidence-sufficiency dimensions present (§7).'
          : `Insufficient evidence (§7): missing ${missing.join(', ')}. Ambiguous observations must not be confirmed.`,
    };
  }
}
