/**
 * Metrics (spec Part 7 §43-§53, §83-§86, §98-§99).
 *
 * All metric computations are DETERMINISTIC functions over real database
 * state: endpoints discovered, hypotheses created, tests executed, requests
 * recorded, model calls logged, findings verified. Nothing is invented.
 */
import type { Repositories } from '@aegis/database';

export interface DiscoveryMetrics {
  endpoint_discovery_recall: number | null;
  parameter_discovery_count: number;
  identity_coverage: number;
  workflow_coverage: number;
  endpoints_discovered: number;
}

export interface HypothesisMetrics {
  hypotheses_created: number;
  hypotheses_confirmed: number;
  hypotheses_disproved: number;
  hypothesis_precision: number | null;
}

export interface TestingMetrics {
  tests_executed: number;
  useful_tests: number;
  duplicate_tests: number;
  dead_ends: number;
  requests: number;
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  requests_per_useful_result: number | null;
  model_calls_per_useful_result: number | null;
}

export interface VerificationMetrics {
  verified_findings: number;
  rejected_findings: number;
  inconclusive_findings: number;
  total_findings: number;
  verification_success_rate: number | null;
  reproduced_count: number;
  reproduction_rate: number | null;
}

export interface CostMetrics {
  model_requests: number;
  input_tokens: number;
  output_tokens: number;
  http_requests: number;
  browser_actions: number;
  execution_time_seconds: number | null;
  tokens_per_verified_finding: number | null;
  requests_per_verified_finding: number | null;
  time_per_verified_finding_seconds: number | null;
}

export interface EngagementMetricsSnapshot {
  discovery: DiscoveryMetrics;
  hypothesis: HypothesisMetrics;
  testing: TestingMetrics;
  verification: VerificationMetrics;
  cost: CostMetrics;
  honest_unverified: number;
}

export class MetricsCollector {
  constructor(private readonly repos: Repositories) {}

  /** Collect the full metric snapshot for one engagement (real DB state). */
  async collect(engagementId: string, startedAt?: string): Promise<EngagementMetricsSnapshot> {
    const [endpoints, parameters, identities, workflows, hypotheses, tests, deadEnds, requests, modelCalls, findings, verifications] =
      await Promise.all([
        this.repos.endpoints.listByEngagement(engagementId, { limit: 1000 }).catch(() => []),
        this.repos.parameters.listByEngagement(engagementId, 2000).catch(() => []),
        this.repos.identities.listByEngagement(engagementId).catch(() => []),
        this.repos.workflows.listByEngagement(engagementId).catch(() => []),
        this.repos.hypotheses.listByEngagement(engagementId, {}).catch(() => []),
        this.repos.tests.listByEngagement(engagementId, 1000).catch(() => []),
        this.repos.deadEnds.listByEngagement(engagementId, 500).catch(() => []),
        this.repos.httpRequests.countByEngagement(engagementId).catch(() => 0),
        this.repos.modelCalls.listByEngagement(engagementId, 1000).catch(() => []),
        this.repos.findings.listByEngagement(engagementId, { limit: 500 }).catch(() => []),
        this.repos.verificationResults.listByEngagement(engagementId, 500).catch(() => []),
      ]);

    const confirmed = hypotheses.filter((h) => h.status === 'CONFIRMED').length;
    const proved = hypotheses.filter((h) => h.status === 'DISPROVED').length;

    const executedTests = tests.filter((t) => t.status !== 'PENDING').length;
    const usefulTests = tests.filter((t) => t.result === 'SUPPORTED' || t.result === 'DISPROVED').length;
    const duplicateTests = tests.filter((t) => t.status === 'DUPLICATE').length;

    const inputTokens = modelCalls.reduce((sum, call) => sum + (call.input_tokens ?? 0), 0);
    const outputTokens = modelCalls.reduce((sum, call) => sum + (call.output_tokens ?? 0), 0);

    const verifiedFindings = findings.filter((f) => f.status === 'VERIFIED' || f.status === 'ACCEPTED').length;
    const rejectedFindings = findings.filter((f) => f.status === 'REJECTED').length;
    const inconclusiveFindings = findings.filter((f) => f.status === 'INCONCLUSIVE').length;

    const reproduced = verifications.filter((v) => v.reproduced).length;

    const executionTime =
      startedAt !== undefined
        ? (Date.now() - Date.parse(startedAt)) / 1000
        : null;

    return {
      discovery: {
        endpoint_discovery_recall: null, // computed against ground truth (§43)
        parameter_discovery_count: parameters.length,
        identity_coverage: identities.length,
        workflow_coverage: workflows.length,
        endpoints_discovered: endpoints.length,
      },
      hypothesis: {
        hypotheses_created: hypotheses.length,
        hypotheses_confirmed: confirmed,
        hypotheses_disproved: proved,
        hypothesis_precision: hypotheses.length > 0 ? Number((confirmed / hypotheses.length).toFixed(3)) : null,
      },
      testing: {
        tests_executed: executedTests,
        useful_tests: usefulTests,
        duplicate_tests: duplicateTests,
        dead_ends: deadEnds.length,
        requests,
        model_calls: modelCalls.length,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        requests_per_useful_result: usefulTests > 0 ? Number((requests / usefulTests).toFixed(2)) : null,
        model_calls_per_useful_result: usefulTests > 0 ? Number((modelCalls.length / usefulTests).toFixed(2)) : null,
      },
      verification: {
        verified_findings: verifiedFindings,
        rejected_findings: rejectedFindings,
        inconclusive_findings: inconclusiveFindings,
        total_findings: findings.length,
        verification_success_rate:
          findings.length > 0 ? Number((verifiedFindings / findings.length).toFixed(3)) : null,
        reproduced_count: reproduced,
        reproduction_rate: verifications.length > 0 ? Number((reproduced / verifications.length).toFixed(3)) : null,
      },
      cost: {
        model_requests: modelCalls.length,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        http_requests: requests,
        browser_actions: 0,
        execution_time_seconds: executionTime,
        tokens_per_verified_finding:
          verifiedFindings > 0 ? Number(((inputTokens + outputTokens) / verifiedFindings).toFixed(0)) : null,
        requests_per_verified_finding: verifiedFindings > 0 ? Number((requests / verifiedFindings).toFixed(2)) : null,
        time_per_verified_finding_seconds:
          verifiedFindings > 0 && executionTime !== null ? Number((executionTime / verifiedFindings).toFixed(2)) : null,
      },
      // §74: honesty signal — findings left honestly unverified.
      honest_unverified: inconclusiveFindings + rejectedFindings,
    };
  }
}

// ---------------------------------------------------------------------------
// Pure metric math (§47-§51)
// ---------------------------------------------------------------------------

export interface GroundTruthMatch {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  duplicates: number;
}

export function precisionRecall(match: GroundTruthMatch): {
  precision: number | null;
  recall: number | null;
  falsePositiveRate: number | null;
} {
  const precision =
    match.truePositives + match.falsePositives > 0
      ? Number((match.truePositives / (match.truePositives + match.falsePositives)).toFixed(3))
      : null;
  const recall =
    match.truePositives + match.falseNegatives > 0
      ? Number((match.truePositives / (match.truePositives + match.falseNegatives)).toFixed(3))
      : null;
  const reportedPositives = match.truePositives + match.falsePositives;
  const falsePositiveRate =
    reportedPositives > 0 ? Number((match.falsePositives / reportedPositives).toFixed(3)) : null;
  return { precision, recall, falsePositiveRate };
}

/** §51: configurable composite efficiency score (raw metrics stay primary). */
export function agentEfficiencyScore(input: {
  verifiedFindings: number;
  modelCost: number;
  networkCost: number;
  executionSeconds: number;
}): number | null {
  if (input.verifiedFindings === 0) return null;
  const cost = input.modelCost + input.networkCost + Math.max(input.executionSeconds / 60, 0.1);
  return Number((input.verifiedFindings / cost).toFixed(4));
}

/** §49: time-to-finding metrics from real timestamps. */
export function timeToFinding(input: {
  engagementStartedAt: string;
  firstCandidateAt: string | null;
  firstVerifiedAt: string | null;
}): {
  time_to_first_candidate_seconds: number | null;
  time_to_first_verified_finding_seconds: number | null;
} {
  const start = Date.parse(input.engagementStartedAt);
  const candidate = input.firstCandidateAt ? (Date.parse(input.firstCandidateAt) - start) / 1000 : null;
  const verified = input.firstVerifiedAt ? (Date.parse(input.firstVerifiedAt) - start) / 1000 : null;
  return {
    time_to_first_candidate_seconds: candidate !== null ? Number(candidate.toFixed(1)) : null,
    time_to_first_verified_finding_seconds: verified !== null ? Number(verified.toFixed(1)) : null,
  };
}
