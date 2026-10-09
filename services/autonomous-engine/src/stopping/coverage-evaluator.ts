/**
 * Coverage evaluator (spec Part 6 §51).
 *
 * Tracks coverage across hosts, applications, pages, endpoints,
 * parameters, identities, workflows, states, technologies and hypothesis
 * classes. Coverage is a PLANNING SIGNAL, not proof of security — the
 * report states this explicitly (§51).
 */
import type { Repositories } from '@aegis/database';
import type { CoverageReport } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import type { PlatformEvent } from '@aegis/contracts';
import type { EventBus } from '@aegis/events';

export class CoverageEvaluator {
  constructor(
    private readonly deps: { repos: Repositories; eventBus: EventBus },
  ) {}

  /** Compute the coverage report (§51) + persist COVERAGE_UPDATED event. */
  async evaluate(engagementId: string): Promise<CoverageReport> {
    const [endpoints, parameters, identities, workflows, objects, hypotheses, tests, authzMatrix] =
      await Promise.all([
        this.deps.repos.endpoints.listByEngagement(engagementId, { limit: 500 }),
        this.deps.repos.parameters.listByEngagement(engagementId, 1000),
        this.deps.repos.identities.listByEngagement(engagementId),
        this.deps.repos.workflows.listByEngagement(engagementId),
        this.deps.repos.objectCandidates.listByEngagement(engagementId, 500),
        this.deps.repos.hypotheses.listByEngagement(engagementId, { limit: 300 }),
        this.deps.repos.tests.listByEngagement(engagementId, 500),
        this.deps.repos.authzMatrix.listByEngagement(engagementId, 1000),
      ]);

    const testedTargets = new Set(tests.filter((t) => t.status === 'COMPLETED').map((t) => t.target));
    const coveredEndpoints = endpoints.filter((e) => testedTargets.has(e.canonical_path)).length;
    const nonAnonymous = identities.filter((i) => i.type !== 'ANONYMOUS');
    const coveredIdentities = new Set(
      tests.filter((t) => t.identity).map((t) => t.identity),
    ).size;
    const confirmedWorkflows = workflows.filter((w) => w.status === 'CONFIRMED').length;

    // Hypothesis-class coverage (§51 example): fraction of hypotheses of a
    // class that reached a terminal verdict.
    const hypothesisCoverage: Record<string, number> = {};
    const byType = new Map<string, { total: number; concluded: number }>();
    for (const hypothesis of hypotheses) {
      const entry = byType.get(hypothesis.type) ?? { total: 0, concluded: 0 };
      entry.total += 1;
      if (hypothesis.status === 'CONFIRMED' || hypothesis.status === 'DISPROVED') entry.concluded += 1;
      byType.set(hypothesis.type, entry);
    }
    for (const [type, entry] of byType) {
      hypothesisCoverage[type] = Number((entry.concluded / entry.total).toFixed(2));
    }

    const matrixCells = authzMatrix.length;
    const matrixCovered = authzMatrix.filter((m) => m.outcome !== 'UNKNOWN').length;

    const report: CoverageReport = {
      engagement_id: engagementId,
      endpoint_coverage: ratio(coveredEndpoints, endpoints.length),
      identity_coverage: ratio(Math.min(coveredIdentities, nonAnonymous.length), Math.max(1, nonAnonymous.length)),
      workflow_coverage: ratio(confirmedWorkflows, workflows.length),
      parameter_coverage: ratio(
        parameters.filter(() => testedTargets.size > 0).length,
        Math.max(1, parameters.length),
      ),
      object_coverage: ratio(
        objects.filter((o) => o.observation_count >= 2).length,
        Math.max(1, objects.length),
      ),
      hypothesis_coverage: hypothesisCoverage,
      counts: {
        endpoints: endpoints.length,
        parameters: parameters.length,
        identities: identities.length,
        workflows: workflows.length,
        objects: objects.length,
        hypotheses: hypotheses.length,
        tests: tests.length,
        authorization_matrix_cells: matrixCells,
        authorization_matrix_covered: matrixCovered,
      },
      note: 'Coverage is a planning signal, not proof of security (§51).',
    };

    const event: PlatformEvent = {
      type: 'COVERAGE_UPDATED',
      engagement_id: engagementId,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: {
        endpoint_coverage: report.endpoint_coverage,
        identity_coverage: report.identity_coverage,
        workflow_coverage: report.workflow_coverage,
      },
      occurred_at: new Date().toISOString(),
      dedup_key: `coverage:${engagementId}:${Date.now()}`,
    };
    await this.deps.eventBus.publish(event).catch(() => undefined);
    return report;
  }
}

function ratio(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  return Number(Math.min(1, numerator / denominator).toFixed(2));
}
