import type { ReactNode } from 'react';
import { useCallback, useState } from 'react';
import { z } from 'zod';
import {
  AgentMetricsResponseSchema,
  AgentRunResponseSchema,
  HypothesisResponseSchema,
  StrategyResponseSchema,
  DeadEndResponseSchema,
  TaskResponseSchema,
  pageSchema,
} from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';
import { StatusBadge } from '../../components/StatusBadge.js';

const RunsPageSchema = pageSchema(AgentRunResponseSchema);
const TasksPageSchema = pageSchema(TaskResponseSchema);
const HypothesesPageSchema = pageSchema(HypothesisResponseSchema);
const StrategiesPageSchema = pageSchema(StrategyResponseSchema);
const DeadEndsPageSchema = pageSchema(DeadEndResponseSchema);

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function AgentTab({
  engagementId,
  engagementStatus,
  mode,
}: {
  engagementId: string;
  engagementStatus: string;
  mode: 'PENTEST' | 'CTF';
}): ReactNode {
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const runs = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/runs`, RunsPageSchema),
    [engagementId],
  );
  const tasks = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/tasks?limit=200`, TasksPageSchema),
    [engagementId],
  );
  const hypotheses = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/hypotheses`, HypothesesPageSchema),
    [engagementId],
  );
  const strategies = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/strategies`, StrategiesPageSchema),
    [engagementId],
  );
  const deadEnds = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/dead-ends`, DeadEndsPageSchema),
    [engagementId],
  );

  const refreshAll = useCallback(() => {
    runs.reload();
    tasks.reload();
    hypotheses.reload();
    strategies.reload();
    deadEnds.reload();
  }, [runs, tasks, hypotheses, strategies, deadEnds]);

  const control = useCallback(
    async (action: 'start' | 'pause' | 'resume' | 'cancel', runId?: string) => {
      setActionError(null);
      setBusy(action);
      try {
        if (action === 'start') {
          await apiRequest('POST', `/api/engagements/${engagementId}/runs`, AgentRunResponseSchema, {});
        } else if (runId) {
          const runControlSchema = z.object({
            paused: z.boolean().optional(),
            resumed: z.boolean().optional(),
            cancelled: z.boolean().optional(),
            run: AgentRunResponseSchema.nullable().optional(),
          });
          const cancelledSchema = z.object({ cancelled: z.boolean() });
          await apiRequest(
            'POST',
            `/api/engagements/${engagementId}/runs/${runId}/${action}`,
            action === 'cancel' ? cancelledSchema : runControlSchema,
            {},
          );
        }
        refreshAll();
      } catch (err) {
        setActionError(
          err instanceof ApiError
            ? `${err.message}${err.details ? `\n${JSON.stringify(err.details)}` : ''}`
            : 'Unexpected agent control error',
        );
      } finally {
        setBusy(null);
      }
    },
    [engagementId, refreshAll],
  );

  const activeRun = runs.data?.items.find((run) =>
    ['CREATED', 'INITIALIZING', 'RUNNING', 'WAITING', 'PAUSED'].includes(run.status),
  );
  const runControl: 'start' | 'pause' | 'resume' | 'cancel' | 'none' = !activeRun
    ? 'start'
    : activeRun.status === 'PAUSED'
      ? 'resume'
      : 'cancel';

  return (
    <div>
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="toolbar">
          <div className="card-title" style={{ margin: 0, border: 'none' }}>
            Autonomous agent {activeRun ? <StatusBadge status={activeRun.status} /> : null}
          </div>
          <div className="actions-row" style={{ margin: 0 }}>
            <button
              type="button"
              className="btn btn-small"
              onClick={refreshAll}
              disabled={busy !== null}
            >
              Refresh
            </button>
            {runControl === 'start' && (
              <button
                type="button"
                className="btn btn-primary btn-small"
                disabled={busy !== null || engagementStatus !== 'RUNNING'}
                onClick={() => void control('start')}
                title={engagementStatus !== 'RUNNING' ? 'Start the engagement first' : undefined}
              >
                {busy === 'start' ? 'Starting…' : 'Start agent run'}
              </button>
            )}
            {activeRun && activeRun.status !== 'PAUSED' && (
              <button
                type="button"
                className="btn btn-small"
                disabled={busy !== null}
                onClick={() => void control('pause', activeRun.id)}
              >
                Pause
              </button>
            )}
            {activeRun && activeRun.status === 'PAUSED' && (
              <button
                type="button"
                className="btn btn-small"
                disabled={busy !== null}
                onClick={() => void control('resume', activeRun.id)}
              >
                Resume
              </button>
            )}
            {activeRun && (
              <button
                type="button"
                className="btn btn-danger btn-small"
                disabled={busy !== null}
                onClick={() => void control('cancel', activeRun.id)}
              >
                Stop
              </button>
            )}
          </div>
        </div>
        <ErrorBanner message={actionError} />
        {runs.loading && <Loading label="loading agent runs" />}
        {runs.error && <ErrorBanner message={runs.error} />}
        {runs.data && runs.data.items.length === 0 && (
          <EmptyState>
            No agent runs yet. The autonomous loop (strategic leader → tasks → workers →
            observations → replanning) starts when you start a run on a RUNNING engagement.
          </EmptyState>
        )}
        {runs.data && runs.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Cycles</th>
                <th>Leader model</th>
                <th>Worker model</th>
                <th>Started</th>
                <th>Ended</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run) => (
                <tr key={run.id}>
                  <td className="mono">{run.id.slice(0, 12)}…</td>
                  <td>
                    <StatusBadge status={run.status} />
                  </td>
                  <td>{String((run.metrics.cycles as number | undefined) ?? 0)}</td>
                  <td className="mono">{run.leader_model}</td>
                  <td className="mono">{run.worker_model}</td>
                  <td>{run.started_at ? run.started_at.slice(0, 19).replace('T', ' ') : '—'}</td>
                  <td>{run.ended_at ? run.ended_at.slice(0, 19).replace('T', ' ') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="page-subtitle" style={{ marginTop: 8 }}>
          Mode: {mode}. Human overrides (clues, hypothesis priority, task cancellation, verification
          requests) are available via the API <span className="mono">POST /api/engagements/:id/overrides</span>.
        </p>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">Hypotheses {hypotheses.data ? `(${hypotheses.data.total})` : ''}</div>
        {hypotheses.loading && <Loading label="loading hypotheses" />}
        {hypotheses.error && <ErrorBanner message={hypotheses.error} />}
        {hypotheses.data && hypotheses.data.items.length === 0 && (
          <EmptyState>No hypotheses yet — the leader forms them from observations.</EmptyState>
        )}
        {hypotheses.data && hypotheses.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Hypothesis</th>
                <th>Type</th>
                <th>Status</th>
                <th>Confidence</th>
                <th>Priority</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {hypotheses.data.items.map((h) => (
                <tr key={h.id}>
                  <td style={{ maxWidth: 420 }}>{h.statement}</td>
                  <td>{h.type}</td>
                  <td>
                    <StatusBadge status={h.status} />
                  </td>
                  <td>{pct(h.confidence)}</td>
                  <td>{pct(h.priority)}</td>
                  <td>{h.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">Tasks {tasks.data ? `(${tasks.data.total})` : ''}</div>
        {tasks.loading && <Loading label="loading tasks" />}
        {tasks.error && <ErrorBanner message={tasks.error} />}
        {tasks.data && tasks.data.items.length === 0 && <EmptyState>No tasks created yet.</EmptyState>}
        {tasks.data && tasks.data.items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>Objective</th>
                <th>Type</th>
                <th>Worker</th>
                <th>Status</th>
                <th>Priority</th>
                <th>Attempts</th>
                <th>Tools</th>
              </tr>
            </thead>
            <tbody>
              {tasks.data.items.map((t) => (
                <tr key={t.id}>
                  <td style={{ maxWidth: 380 }}>{t.objective}</td>
                  <td>{t.type}</td>
                  <td>{t.worker_type}</td>
                  <td>
                    <StatusBadge status={t.status} />
                  </td>
                  <td>{pct(t.priority)}</td>
                  <td>
                    {t.attempts}/{t.max_attempts}
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {t.allowed_tools.slice(0, 3).join(', ')}
                    {t.allowed_tools.length > 3 ? ` +${t.allowed_tools.length - 3}` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">Strategy history</div>
        {strategies.loading && <Loading label="loading strategies" />}
        {strategies.error && <ErrorBanner message={strategies.error} />}
        {strategies.data && strategies.data.items.length === 0 && (
          <EmptyState>No strategy changes recorded yet.</EmptyState>
        )}
        {strategies.data && strategies.data.items.length > 0 && (
          <div>
            {strategies.data.items.map((s) => (
              <div className="timeline-item" key={s.id}>
                <div className="timeline-type">
                  v{s.version} · focus: {s.focus}
                </div>
                <div className="timeline-payload">{s.summary}</div>
                <div className="timeline-time">reason: {s.reason}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-title">Dead ends {deadEnds.data ? `(${deadEnds.data.total})` : ''}</div>
        {deadEnds.loading && <Loading label="loading dead ends" />}
        {deadEnds.error && <ErrorBanner message={deadEnds.error} />}
        {deadEnds.data && deadEnds.data.items.length === 0 && (
          <EmptyState>No dead ends recorded yet.</EmptyState>
        )}
        {deadEnds.data && deadEnds.data.items.length > 0 && (
          <div>
            {deadEnds.data.items.map((d) => (
              <div className="timeline-item" key={d.id}>
                <div className="timeline-type">{d.description}</div>
                <div className="timeline-payload">{d.reason}</div>
                <div className="timeline-time">
                  {d.tests.length} exhausted test(s){d.hypothesis_id ? ` · ${d.hypothesis_id}` : ''}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <MetricsBlock engagementId={engagementId} />
    </div>
  );
}

function MetricsBlock({ engagementId }: { engagementId: string }): ReactNode {
  const metrics = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/agent-metrics`, AgentMetricsResponseSchema),
    [engagementId],
  );
  if (metrics.loading || metrics.error || !metrics.data) return null;
  const m = metrics.data;
  const stats: Array<[string, string]> = [
    ['Cycles', `${m.cycles.total} (${m.cycles.rejected} rejected)`],
    ['Tasks', `${m.tasks.completed}/${m.tasks.total} completed, ${m.tasks.failed} failed`],
    ['Hypotheses', `${m.hypotheses.active} active, ${m.hypotheses.confirmed} confirmed, ${m.hypotheses.disproved} disproved`],
    ['Dead ends', String(m.hypotheses.dead_ends)],
    ['Observations', String(m.observations)],
    ['Findings', String(m.findings)],
    ['Model calls', String(m.tokens.model_calls)],
    ['Tokens', `${m.tokens.input_tokens} in / ${m.tokens.output_tokens} out`],
    ['Tool calls', String(m.tool_calls)],
  ];
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="card-title">Agent metrics</div>
      <table className="table">
        <tbody>
          {stats.map(([label, value]) => (
            <tr key={label}>
              <td style={{ width: 160 }}>{label}</td>
              <td>{value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
