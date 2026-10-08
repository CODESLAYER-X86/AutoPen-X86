/**
 * Agent observability (spec Part 2 §58).
 *
 * Aggregates the metrics the UI visualizes: cycles, leader/worker calls,
 * tokens, tasks, retries, hypotheses, dead ends, tool calls, network
 * activity, duration. All values are derived from persisted state — no
 * in-memory-only numbers.
 */
import type { Repositories } from '@aegis/database';

export interface AgentMetrics {
  runs: {
    total: number;
    active: number;
    completed: number;
    failed: number;
    cancelled: number;
  };
  cycles: {
    total: number;
    valid: number;
    rejected: number;
  };
  tasks: {
    total: number;
    completed: number;
    partial: number;
    failed: number;
    cancelled: number;
    pending: number;
    retries: number;
  };
  hypotheses: {
    total: number;
    active: number;
    confirmed: number;
    disproved: number;
    abandoned: number;
    dead_ends: number;
  };
  workers: {
    attempts: number;
    failures: number;
    needs_blocked: number;
  };
  tokens: {
    model_calls: number;
    input_tokens: number;
    output_tokens: number;
    by_purpose: Record<string, { calls: number; input: number; output: number }>;
  };
  tool_calls: number;
  network_requests: number;
  observations: number;
  findings: number;
  tests: number;
}

export interface MetricsCollectorDeps {
  repos: Repositories;
}

export class AgentMetricsCollector {
  constructor(private readonly deps: MetricsCollectorDeps) {}

  async collect(engagementId: string): Promise<AgentMetrics> {
    const { repos } = this.deps;

    const [runs, tasksByStatus, hypothesisCounts, usage, tokenUsage, observationCount, findingCount, testCount, deadEndCount] =
      await Promise.all([
        repos.agentRuns.listByEngagement(engagementId, 200),
        repos.tasks.countByStatus(engagementId),
        repos.hypotheses.countByStatus(engagementId),
        repos.budgets.getUsage(engagementId),
        repos.modelCalls.usageByPurpose(engagementId),
        repos.observations.countByEngagement(engagementId),
        repos.findings.listByEngagement(engagementId, { statuses: ['CONFIRMED'] }),
        repos.tests.countByEngagement(engagementId),
        repos.deadEnds.countByEngagement(engagementId),
      ]);

    // Decisions per engagement (listByRun needs a run; query via tasks hook
    // instead — decisions are per-run, runs are per-engagement).
    const decisions: { validation_status: string }[] = [];
    for (const run of runs) {
      const runDecisions = await repos.agentDecisions.listByRun(run.id, 500);
      decisions.push(
        ...runDecisions.map((d) => ({ validation_status: d.validation_status })),
      );
    }

    // Worker attempt stats per engagement.
    const workerStats = await this.collectWorkerStats(engagementId);

    const pending: number =
      tasksByStatus.CREATED +
      tasksByStatus.QUEUED +
      tasksByStatus.READY +
      tasksByStatus.RUNNING +
      tasksByStatus.WAITING +
      tasksByStatus.RECOVERY_PENDING;

    const byPurpose: Record<string, { calls: number; input: number; output: number }> = {};
    let totalCalls = 0;
    let inputTokens = 0;
    let outputTokens = 0;
    for (const row of tokenUsage) {
      byPurpose[row.purpose] = {
        calls: row.calls,
        input: row.input_tokens,
        output: row.output_tokens,
      };
      totalCalls += row.calls;
      inputTokens += row.input_tokens;
      outputTokens += row.output_tokens;
    }

    const taskTotal: number = (Object.values(tasksByStatus) as number[]).reduce((a, b) => a + b, 0);
    const hypTotal: number = (Object.values(hypothesisCounts) as number[]).reduce((a, b) => a + b, 0);
    const activeHypotheses: number =
      hypothesisCounts.PROPOSED +
      hypothesisCounts.ACTIVE +
      hypothesisCounts.TESTING +
      hypothesisCounts.SUPPORTED;

    return {
      runs: {
        total: runs.length,
        active: runs.filter((r: { status: string }) => ['CREATED', 'INITIALIZING', 'RUNNING', 'WAITING', 'PAUSED'].includes(r.status)).length,
        completed: runs.filter((r: { status: string }) => r.status === 'COMPLETED').length,
        failed: runs.filter((r: { status: string }) => r.status === 'FAILED').length,
        cancelled: runs.filter((r: { status: string }) => r.status === 'CANCELLED').length,
      },
      cycles: {
        total: decisions.length,
        valid: decisions.filter((d) => d.validation_status === 'VALID').length,
        rejected: decisions.filter(
          (d) => d.validation_status === 'REJECTED' || d.validation_status === 'FAILED',
        ).length,
      },
      tasks: {
        total: taskTotal,
        completed: tasksByStatus.COMPLETED,
        partial: tasksByStatus.PARTIAL,
        failed: tasksByStatus.FAILED,
        cancelled: tasksByStatus.CANCELLED,
        pending,
        retries: workerStats.retries,
      },
      hypotheses: {
        total: hypTotal,
        active: activeHypotheses,
        confirmed: hypothesisCounts.CONFIRMED,
        disproved: hypothesisCounts.DISPROVED,
        abandoned: hypothesisCounts.ABANDONED,
        dead_ends: deadEndCount,
      },
      workers: workerStats,
      tokens: {
        model_calls: totalCalls,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        by_purpose: byPurpose,
      },
      tool_calls: usage.tool_calls,
      network_requests: usage.network_requests,
      observations: observationCount,
      findings: findingCount.length,
      tests: testCount,
    };
  }

  private async collectWorkerStats(
    engagementId: string,
  ): Promise<{ attempts: number; failures: number; needs_blocked: number; retries: number }> {
    // Attempts are derived from tasks (attempts column) + task status rows.
    const tasks = await this.deps.repos.tasks.listByEngagement(engagementId, { limit: 500 });
    let attempts = 0;
    let retries = 0;
    for (const task of tasks) {
      attempts += task.attempts;
      retries += Math.max(0, task.attempts - 1);
    }
    const failed = tasks.filter(
      (t) =>
        t.failure_code === 'WORKER_BLOCKED' ||
        t.failure_code === 'WORKER_NEEDS_CONTEXT' ||
        t.failure_code === 'WORKER_NEEDS_TOOL' ||
        t.failure_code === 'WORKER_NEEDS_IDENTITY',
    ).length;
    return {
      attempts,
      failures: tasks.filter((t) => t.status === 'FAILED').length,
      needs_blocked: failed,
      retries,
    };
  }
}
