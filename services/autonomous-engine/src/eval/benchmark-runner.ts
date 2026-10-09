/**
 * Benchmark runner (spec Part 6 §79, §84).
 *
 * Computes metrics from the persisted state of a benchmark engagement:
 * time to first/verified finding, false-positive rate, duplicate-test rate,
 * coverage, requests/model-tokens per finding, verification success and
 * CTF solve rate. A good agent solves with FEWER meaningful experiments
 * (§84), so per-finding efficiency is a first-class metric.
 */
import type { Repositories } from '@aegis/database';
import type { BenchmarkMetrics, CoverageReport } from '@aegis/contracts';

export interface BenchmarkInput {
  engagementId: string;
  startedAt: number;
  finishedAt: number;
  solved: boolean;
  coverage: CoverageReport | null;
  expectedFindingsTotal: number;
  expectedFindingsFound: number;
  expectedDeadEndsAvoided: number;
}

export class BenchmarkRunner {
  constructor(private readonly repos: Repositories) {}

  /** Compute the benchmark metrics (§79). */
  async compute(input: BenchmarkInput): Promise<BenchmarkMetrics> {
    const [findings, tests, modelCalls, verifications] = await Promise.all([
      this.repos.findings.listByEngagement(input.engagementId, { limit: 200 }),
      this.repos.tests.listByEngagement(input.engagementId, 500),
      this.repos.modelCalls.listByEngagement(input.engagementId, 500),
      this.repos.verifications.listByEngagement(input.engagementId, 200),
    ]);
    const httpCount = await this.repos.httpRequests.countByEngagement(input.engagementId);

    const verified = findings.filter((f) => f.status === 'CONFIRMED' || f.status === 'VERIFIED');
    const rejected = findings.filter((f) => f.status === 'REJECTED');
    const duplicates = tests.filter((t) => t.status === 'DUPLICATE').length;
    const totalTokens = modelCalls.reduce(
      (sum, call) => sum + (call.input_tokens ?? 0) + (call.output_tokens ?? 0),
      0,
    );
    const concludedVerifications = verifications.filter(
      (v) => v.status === 'VERIFIED' || v.status === 'REFUTED',
    );
    const successfulVerifications = verifications.filter((v) => v.status === 'VERIFIED');

    const firstFinding = [...findings].sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at))[0];
    const firstVerified = [...verified].sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at))[0];

    return {
      time_to_first_finding_ms: firstFinding ? Date.parse(firstFinding.created_at) - input.startedAt : null,
      time_to_verified_finding_ms: firstVerified ? Date.parse(firstVerified.created_at) - input.startedAt : null,
      time_to_solve_ms: input.solved ? input.finishedAt - input.startedAt : null,
      false_positive_rate: findings.length > 0 ? Number((rejected.length / findings.length).toFixed(3)) : null,
      duplicate_test_rate: tests.length > 0 ? Number((duplicates / tests.length).toFixed(3)) : null,
      coverage: input.coverage
        ? {
            endpoint_coverage: input.coverage.endpoint_coverage,
            identity_coverage: input.coverage.identity_coverage,
            workflow_coverage: input.coverage.workflow_coverage,
          }
        : null,
      requests_per_finding: verified.length > 0 ? Number((httpCount / verified.length).toFixed(1)) : null,
      model_tokens_per_finding: verified.length > 0 ? Math.round(totalTokens / verified.length) : null,
      knowledge_calls: 0,
      verification_success_rate:
        concludedVerifications.length > 0
          ? Number((successfulVerifications.length / concludedVerifications.length).toFixed(3))
          : null,
      solved: input.solved,
      expected_findings_found: input.expectedFindingsFound,
      expected_findings_total: input.expectedFindingsTotal,
      expected_dead_ends_avoided: input.expectedDeadEndsAvoided,
      total_tests: tests.length,
      total_model_calls: modelCalls.length,
      total_http_requests: httpCount,
    };
  }

  /** Persist a completed benchmark run (§79). */
  async record(benchmark: string, engagementId: string, outcome: 'COMPLETED' | 'SOLVED' | 'STOPPED' | 'FAILED', metrics: BenchmarkMetrics): Promise<void> {
    const run = await this.repos.benchmarkRuns.create(benchmark, engagementId);
    await this.repos.benchmarkRuns.complete(run.id, outcome, metrics as unknown as Record<string, unknown>);
  }
}
