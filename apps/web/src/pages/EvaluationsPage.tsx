import type { ReactNode } from 'react';
import { useState } from 'react';
import { z } from 'zod';
import { apiRequest, ApiError } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../components/Feedback.js';

const ScenariosSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      kind: z.string(),
      description: z.string(),
      version: z.number(),
      safety_expectations: z.array(z.object({ kind: z.string(), detail: z.string() })),
    }),
  ),
  total: z.number(),
});

const RunsSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      status: z.string(),
      started_by: z.string(),
      started_at: z.string(),
      completed_at: z.string().nullable(),
      is_golden: z.boolean(),
      config: z.record(z.unknown()),
    }),
  ),
  total: z.number(),
});

const ScorecardSchema = z.object({
  run_id: z.string(),
  dimensions: z.record(z.number()),
  metrics: z.record(z.number()),
  note: z.string().optional(),
});

const DIMENSIONS = ['RECON', 'HYPOTHESIS', 'TESTING', 'VERIFICATION', 'REPORTING', 'EFFICIENCY', 'SAFETY'];

export function EvaluationsPage(): ReactNode {
  const [label, setLabel] = useState('adhoc');
  const [golden, setGolden] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<string | null>(null);

  const scenarios = useResource(
    () => apiRequest('GET', '/api/scenarios', ScenariosSchema),
    [],
  );
  const runs = useResource(() => apiRequest('GET', '/api/evaluations', RunsSchema), []);

  const scorecard = useResource(
    async () => {
      if (selectedRun === null) return null;
      try {
        return await apiRequest('GET', `/api/evaluations/${selectedRun}/scorecard`, ScorecardSchema);
      } catch {
        return null;
      }
    },
    [selectedRun],
  );

  const runEvaluation = async (): Promise<void> => {
    const scenarioIds = scenarios.data?.items.map((s) => s.id) ?? [];
    if (scenarioIds.length === 0) {
      setActionError('No scenarios available to run.');
      return;
    }
    setBusy(true);
    setActionError(null);
    try {
      await apiRequest('POST', '/api/evaluations/run', z.any(), {
        scenario_ids: scenarioIds,
        label,
        strategic_model: 'mock',
        tactical_model: 'mock',
        prompt_versions: { leader: 'v1', worker: 'v1' },
        tool_versions: {},
        golden,
        tags: ['ui'],
      });
      runs.reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="card">
        <div className="card-title">Evaluation & Benchmarks</div>
        <p className="page-subtitle">
          Benchmarks measure the ENTIRE loop (recon → hypothesis → test → verification → finding →
          report), including safety: scope violations, prompt-injection containment, hallucinated
          evidence rejection, repetition memory and resource awareness (§40, §76-§82). Runs boot
          LOCAL fixtures only — never external targets.
        </p>
        <div className="toolbar" style={{ gap: 8, flexWrap: 'wrap' }}>
          <label>
            Label <input value={label} onChange={(e) => setLabel(e.target.value)} />
          </label>
          <label style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
            <input type="checkbox" checked={golden} onChange={(e) => setGolden(e.target.checked)} />
            Golden run (§90)
          </label>
          <button type="button" className="btn" disabled={busy} onClick={runEvaluation}>
            {busy ? 'Running…' : `Run all ${scenarios.data?.items.length ?? 0} scenarios`}
          </button>
        </div>
        {actionError && <ErrorBanner message={actionError} />}
        {scenarios.loading && <Loading label="loading scenarios" />}
        {scenarios.error && <ErrorBanner message={scenarios.error} />}
        {scenarios.data && scenarios.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Kind</th>
                <th>Safety expectations</th>
                <th>v</th>
              </tr>
            </thead>
            <tbody>
              {scenarios.data.items.map((scenario) => (
                <tr key={scenario.id}>
                  <td title={scenario.description} style={{ maxWidth: 260 }}>
                    {scenario.name}
                  </td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>
                    {scenario.kind}
                  </td>
                  <td style={{ fontSize: '0.78rem' }}>
                    {scenario.safety_expectations.map((s) => s.kind).join(', ') || '—'}
                  </td>
                  <td>{scenario.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="toolbar">
          <div className="card-title" style={{ margin: 0, border: 'none' }}>
            Runs {runs.data ? `(${runs.data.total})` : ''}
          </div>
          <button type="button" className="btn btn-small" onClick={runs.reload}>
            Refresh
          </button>
        </div>
        {runs.loading && <Loading label="loading runs" />}
        {runs.error && <ErrorBanner message={runs.error} />}
        {runs.data && runs.data.items.length === 0 && (
          <EmptyState>No evaluation runs yet. Run the scenario suite above.</EmptyState>
        )}
        {runs.data && runs.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Label</th>
                <th>Golden</th>
                <th>Started</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id}>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>
                    {run.id.slice(0, 16)}…
                  </td>
                  <td>{run.status}</td>
                  <td>{String((run.config as { label?: string }).label ?? '—')}</td>
                  <td>{run.is_golden ? '★' : ''}</td>
                  <td>{run.started_at.slice(0, 19).replace('T', ' ')}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-small"
                      onClick={() => setSelectedRun(run.id === selectedRun ? null : run.id)}
                    >
                      {run.id === selectedRun ? 'Hide' : 'Scorecard'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {selectedRun && (
          <div style={{ marginTop: 12 }}>
            {scorecard.loading && <Loading label="loading scorecard" />}
            {scorecard.data ? (
              <div className="card" style={{ padding: 12 }}>
                <strong>End-to-end scorecard (§87) — {selectedRun.slice(0, 16)}…</strong>
                <table className="table" style={{ marginTop: 8 }}>
                  <thead>
                    <tr>
                      <th>Dimension</th>
                      <th>Score</th>
                      <th>Bar</th>
                    </tr>
                  </thead>
                  <tbody>
                    {DIMENSIONS.map((dimension) => {
                      const value = scorecard.data?.dimensions[dimension] ?? 0;
                      return (
                        <tr key={dimension}>
                          <td>{dimension}</td>
                          <td>{value.toFixed(3)}</td>
                          <td>
                            <div
                              style={{
                                background: '#e8eaee',
                                borderRadius: 3,
                                height: 8,
                                width: 220,
                              }}
                            >
                              <div
                                style={{
                                  background: dimension === 'SAFETY' && value < 1 ? '#b3261e' : '#1e8e3e',
                                  borderRadius: 3,
                                  height: 8,
                                  width: `${Math.round(value * 220)}px`,
                                }}
                              />
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <div style={{ fontSize: '0.8rem', marginTop: 8 }}>
                  Key metrics:{' '}
                  {['finding_precision', 'finding_recall', 'false_positive_rate', 'tokens_per_finding', 'safety_violations']
                    .map((metric) => `${metric}=${scorecard.data?.metrics[metric] ?? '—'}`)
                    .join(' · ')}
                </div>
                {scorecard.data?.note && <p className="text-muted" style={{ fontSize: '0.78rem' }}>{scorecard.data.note}</p>}
              </div>
            ) : (
              !scorecard.loading && <p className="text-muted">Scorecard not ready for this run.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
