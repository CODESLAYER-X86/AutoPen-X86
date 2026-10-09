/**
 * Part 7 API routes — evaluation system (spec Part 7 §60, §87, §88).
 *
 *  - POST /api/evaluations/run (§60)
 *  - GET  /api/evaluations
 *  - GET  /api/evaluations/:id
 *  - GET  /api/evaluations/:id/metrics
 *  - GET  /api/evaluations/:id/events
 *  - GET  /api/evaluations/:id/findings
 *  - GET  /api/evaluations/:id/scorecard (§87)
 *  - POST /api/evaluations/:id/regression-check (§88-§89)
 *  - GET  /api/scenarios (§41 registry)
 *
 * Evaluation runs boot LOCAL fixtures only — never external targets (§39).
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { NotImplementedError, NotFoundError, ValidationError } from '@aegis/shared';
import {
  CompareEvaluationsRequestSchema,
  ListScenariosQuerySchema,
  RunEvaluationRequestSchema,
} from '@aegis/contracts';
import { parseBody } from '../lib/validate.js';

export async function evaluationRoutes(app: FastifyInstance): Promise<void> {
  const ctx = () => app.ctx;

  const engine = () => {
    const c = ctx();
    if (!c.vr) {
      throw new NotImplementedError(
        'The evaluation engine (Part 7) is disabled in this deployment; set FEATURE_REPORTING=true to enable it',
        'EVALUATION_ENGINE_DISABLED',
      );
    }
    return c.vr.benchmarks;
  };

  const regressionEngine = () => {
    const c = ctx();
    if (!c.vr) {
      throw new NotImplementedError(
        'The evaluation engine (Part 7) is disabled in this deployment; set FEATURE_REPORTING=true to enable it',
        'EVALUATION_ENGINE_DISABLED',
      );
    }
    return c.vr.regression;
  };

  // ------------------------------------------------------------ scenarios (§41)

  app.get('/api/scenarios', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const query = parseBody(ListScenariosQuerySchema, {
      kind: (request.query as { kind?: string }).kind ?? undefined,
      limit: (request.query as { limit?: string }).limit ?? '100',
      offset: (request.query as { offset?: string }).offset ?? '0',
    });
    // Idempotent seeding so the registry is available before the first run.
    await engine().seedScenarios().catch(() => undefined);
    // Ground truth is HIDDEN from the agent side but the operator-facing API
    // exposes the registry for review (§41: controlled ground truth).
    const scenarios = await engine().listScenarios({ kind: query.kind, limit: query.limit });
    return {
      items: scenarios.map((scenario) => ({
        ...scenario,
        expected_findings: scenario.expected_findings.map((f) => ({
          ...f,
          match_tokens: undefined,
        })),
      })),
      total: scenarios.length,
    };
  });

  // ------------------------------------------------------------ run (§60, §42)

  app.post('/api/evaluations/run', async (request: FastifyRequest, reply) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(RunEvaluationRequestSchema, request.body ?? {});
    const outcome = await engine().runEvaluation({
      scenarioIds: body.scenario_ids,
      label: body.label,
      startedBy: request.user.id,
      strategicModel: body.strategic_model,
      tacticalModel: body.tactical_model,
      promptVersions: body.prompt_versions,
      toolVersions: body.tool_versions,
      golden: body.golden,
      tags: body.tags,
    });
    await c.audit({
      actorUserId: request.user.id,
      action: 'EVALUATION_RUN_EXECUTED',
      resource: 'evaluation_run',
      resourceId: outcome.runId,
      engagementId: null,
      metadata: { label: body.label, scenarios: body.scenario_ids.length, status: outcome.status },
    });
    return reply.code(outcome.status === 'FAILED' ? 500 : 201).send(outcome);
  });

  app.get('/api/evaluations', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const limit = Number((request.query as { limit?: string }).limit ?? '50');
    const runs = await engine().listRuns({ limit: Number.isFinite(limit) ? Math.min(Math.max(limit, 1), 200) : 50 });
    return { items: runs, total: runs.length };
  });

  const requireRun = async (runId: string) => {
    try {
      return await engine().getRun(runId);
    } catch (error) {
      if (error instanceof NotFoundError) throw error;
      throw error;
    }
  };

  app.get('/api/evaluations/:id', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    return { run: await requireRun(id) };
  });

  app.get('/api/evaluations/:id/metrics', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireRun(id);
    return { metrics: await ctx().repos.evaluationMetrics.listByRun(id) };
  });

  app.get('/api/evaluations/:id/events', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireRun(id);
    return { events: await ctx().repos.evaluationEvents.listByRun(id) };
  });

  app.get('/api/evaluations/:id/findings', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireRun(id);
    return { findings: await ctx().repos.evaluationObservedFindings.listByRun(id) };
  });

  // ---------------------------------------------------------- scorecard (§87)

  app.get('/api/evaluations/:id/scorecard', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireRun(id);
    const metrics = await ctx().repos.evaluationMetrics.listByRun(id, 'run');
    const runMetrics: Record<string, number> = {};
    for (const row of metrics) runMetrics[row.metric] = row.value;
    if (Object.keys(runMetrics).length === 0) {
      throw new ValidationError('Run has no scorecard yet (still running?)', 'SCORECARD_NOT_READY');
    }
    const dimensions: Record<string, number> = {
      RECON: runMetrics['endpoint_discovery_recall'] ?? 0,
      HYPOTHESIS: runMetrics['hypothesis_precision'] ?? 0,
      TESTING: runMetrics['tests_executed'] ? Math.min(1, (runMetrics['useful_tests'] ?? 0) / runMetrics['tests_executed']) : 0,
      VERIFICATION: runMetrics['verification_success_rate'] ?? 0,
      REPORTING: runMetrics['finding_precision'] ?? 0,
      EFFICIENCY: runMetrics['agent_efficiency_score'] ?? 0,
      SAFETY: (runMetrics['safety_violations_total'] ?? 1) === 0 ? 1 : 0,
    };
    return {
      run_id: id,
      dimensions,
      metrics: runMetrics,
      note: 'Scorecard dimensions are bounded [0,1]; SAFETY is binary (§88).',
    };
  });

  // ------------------------------------------------------ regression (§88-§89)

  app.post('/api/evaluations/:id/regression-check', async (request: FastifyRequest) => {
    const c = ctx();
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    const body = (request.body ?? {}) as { baseline_run_id?: string };
    await requireRun(id);
    const outcome = await regressionEngine().check(id, body.baseline_run_id);
    await c.audit({
      actorUserId: request.user.id,
      action: 'EVALUATION_REGRESSION_CHECKED',
      resource: 'evaluation_run',
      resourceId: id,
      engagementId: null,
      metadata: { verdict: outcome.verdict, release_gate: outcome.releaseGate.decision },
    });
    return outcome;
  });

  // ------------------------------------------------------- compare (§60 optional)

  app.post('/api/evaluations/compare', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const body = parseBody(CompareEvaluationsRequestSchema, request.body ?? {});
    const runs = [];
    for (const runId of body.run_ids) {
      const run = await engine().getRun(runId).catch(() => null);
      if (!run) continue;
      const metrics = await ctx().repos.evaluationMetrics.listByRun(runId, 'run');
      const metricMap: Record<string, number> = {};
      for (const row of metrics) metricMap[row.metric] = row.value;
      runs.push({ run_id: runId, label: String((run.config as { label?: string }).label ?? runId), metrics: metricMap });
    }
    if (runs.length < 2) {
      throw new ValidationError('At least two valid runs are required for comparison', 'COMPARE_INSUFFICIENT_RUNS');
    }
    const baselineMetrics = runs[0]!.metrics;
    const deltas: Record<string, Record<string, number>> = {};
    let improved = 0;
    let regressed = 0;
    for (const run of runs.slice(1)) {
      const runDeltas: Record<string, number> = {};
      for (const [metric, value] of Object.entries(run.metrics)) {
        const base = baselineMetrics[metric];
        if (base !== undefined) {
          const delta = Number((value - base).toFixed(3));
          runDeltas[metric] = delta;
          if (metric.includes('violation') || metric.includes('false_positive')) {
            if (delta > 0) regressed++;
            else if (delta < 0) improved++;
          } else if (delta > 0) improved++;
          else if (delta < 0) regressed++;
        }
      }
      deltas[run.run_id] = runDeltas;
    }
    const verdict = improved > regressed ? 'IMPROVED' : regressed > improved ? 'REGRESSED' : 'MIXED';
    return {
      runs,
      deltas,
      verdict,
      notes: [
        'Comparison deltas are relative to the first run (baseline).',
        'Higher-is-better metrics: precision, recall, efficiency. Lower-is-better: violations, false positives.',
      ],
    };
  });

  // ------------------------------------------------------- golden runs (§90)

  app.get('/api/evaluations/:id/golden-comparison', async (request: FastifyRequest) => {
    if (!request.user) throw new Error('auth invariant violated');
    const { id } = request.params as { id: string };
    await requireRun(id);
    return regressionEngine().compareToGolden(id);
  });
}
