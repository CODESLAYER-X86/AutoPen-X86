import type { ReactNode } from 'react';
import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';
import {
  AutonomousStatusResponseSchema,
  TimelineResponseSchema,
  CoverageResponseSchema,
  BranchListResponseSchema,
  ApprovalListResponseSchema,
  CtfResponseSchema,
  TestRegistryResponseSchema,
  type TimelineEntry,
  type ReasoningBranch,
  type ApprovalRecord,
  type CtfContext,
  type CtfClue,
  type FlagCondition,
  type CoverageReport,
  type AutonomousStatusResponse,
  type TestRegistryEntry,
} from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';
import { StatusBadge } from '../../components/StatusBadge.js';

const TERMINAL_PHASES = ['COMPLETED', 'STOPPED', 'CANCELLED', 'FAILED'];

function phaseColor(phase: string): string {
  if (TERMINAL_PHASES.includes(phase)) return 'var(--status-info)';
  if (phase.startsWith('WAITING_FOR')) return 'var(--status-warning)';
  if (phase === 'VERIFICATION' || phase === 'ANALYSIS') return 'var(--status-ok)';
  return 'var(--status-info)';
}

function pct(value: number): string {
  return `${Math.round(value * 100)}%`;
}

function SummaryCounts({ counts, label }: { counts: Record<string, number>; label: string }): ReactNode {
  const entries = Object.entries(counts);
  if (entries.length === 0) {
    return (
      <div className="card" style={{ padding: 12 }}>
        <strong>{label}</strong>
        <p className="muted" style={{ margin: 0 }}>none yet</p>
      </div>
    );
  }
  return (
    <div className="card" style={{ padding: 12 }}>
      <strong>{label}</strong>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 6 }}>
        {entries.map(([key, count]) => (
          <span key={key} className="pill" title={`${count} ${key}`}>
            {key}: <strong>{count}</strong>
          </span>
        ))}
      </div>
    </div>
  );
}

function BranchList({ branches }: { branches: ReasoningBranch[] }): ReactNode {
  if (branches.length === 0) return <EmptyState>No reasoning branches yet — branches appear once hypotheses are generated (§65).</EmptyState>;
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Focus</th>
          <th>Origin</th>
          <th>Hypotheses</th>
          <th>Score</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {branches.map((branch) => (
          <tr key={branch.id}>
            <td className="mono" style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis' }} title={branch.focus}>
              {branch.focus}
            </td>
            <td>{branch.origin}</td>
            <td>{branch.hypothesis_ids.length}</td>
            <td>{branch.score.toFixed(2)}</td>
            <td>
              <StatusBadge status={branch.status} />
              {branch.pruned_reason ? <p className="muted" style={{ margin: 0, fontSize: 11 }}>{branch.pruned_reason}</p> : null}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Approvals({
  approvals,
  onApprove,
  onReject,
  busy,
}: {
  approvals: ApprovalRecord[];
  onApprove: (approval: ApprovalRecord) => void;
  onReject: (approval: ApprovalRecord) => void;
  busy: string | null;
}): ReactNode {
  const pending = approvals.filter((approval) => approval.decision === null);
  if (pending.length === 0) {
    return <EmptyState>No approvals pending — high-risk actions require explicit user approval (§49).</EmptyState>;
  }
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Action</th>
          <th>Risk</th>
          <th>Requested by</th>
          <th>Decision</th>
        </tr>
      </thead>
      <tbody>
        {pending.map((approval) => (
          <tr key={approval.id}>
            <td style={{ maxWidth: 360 }}>{approval.action_summary}</td>
            <td>
              <span className="pill">{approval.risk}</span>
            </td>
            <td className="mono" style={{ fontSize: 11 }}>{approval.requested_by}</td>
            <td>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="button" disabled={busy !== null} onClick={() => onApprove(approval)}>
                  Approve
                </button>
                <button type="button" className="secondary" disabled={busy !== null} onClick={() => onReject(approval)}>
                  Reject
                </button>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CtfPanel({
  context,
  clues,
  flagConditions,
}: {
  context: CtfContext | null;
  clues: CtfClue[];
  flagConditions: FlagCondition[];
}): ReactNode {
  if (!context) {
    return <EmptyState>No CTF challenge loaded — POST /ctf/context to load the challenge description (§29).</EmptyState>;
  }
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="card" style={{ padding: 12 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <strong>{context.title || 'Unnamed challenge'}</strong>
          <StatusBadge status={context.status} />
        </div>
        <p className="muted" style={{ marginTop: 6 }}>{context.description}</p>
        {context.flag_value ? (
          <p className="mono" style={{ color: 'var(--status-ok)' }}>flag: {context.flag_value}</p>
        ) : null}
      </div>
      <div className="card" style={{ padding: 12 }}>
        <strong>Clues ({clues.length})</strong>
        {clues.slice(0, 8).map((clue) => (
          <div key={clue.id} style={{ borderBottom: '1px solid var(--border)', padding: '6px 0' }}>
            <span className="pill">{clue.source}</span>{' '}
            <span style={{ fontSize: 13 }}>{clue.text}</span>
            {clue.interpretations.length > 0 ? (
              <ul style={{ margin: '4px 0 0 16px', fontSize: 12, color: 'var(--text-muted)' }}>
                {clue.interpretations.slice(0, 3).map((interpretation, index) => (
                  <li key={index}>
                    {interpretation.concept} (confidence {interpretation.confidence.toFixed(2)})
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ))}
      </div>
      <div className="card" style={{ padding: 12 }}>
        <strong>Flag conditions</strong>
        {flagConditions.length === 0 ? (
          <p className="muted" style={{ margin: 0 }}>none</p>
        ) : (
          flagConditions.map((condition) => (
            <p key={condition.id} style={{ margin: '4px 0', fontSize: 13 }}>
              <StatusBadge status={condition.status} /> {condition.condition_description}
            </p>
          ))
        )}
      </div>
    </div>
  );
}

function TimelineFeed({ entries }: { entries: TimelineEntry[] }): ReactNode {
  if (entries.length === 0) {
    return <EmptyState>No agent activity yet — the live timeline renders the audit chain (§53).</EmptyState>;
  }
  return (
    <div className="card" style={{ padding: 12, maxHeight: 420, overflowY: 'auto' }}>
      {entries.map((entry) => (
        <div key={entry.event_id} style={{ display: 'flex', gap: 10, borderBottom: '1px solid var(--border)', padding: '4px 0' }}>
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 66 }}>
            {entry.occurred_at.slice(11, 19)}
          </span>
          <span style={{ fontSize: 13 }}>{entry.summary}</span>
        </div>
      ))}
    </div>
  );
}

function TestRegistry({ tests }: { tests: TestRegistryEntry[] }): ReactNode {
  if (tests.length === 0) {
    return <EmptyState>No experiments recorded — the test registry is the agent's experimental memory (§60).</EmptyState>;
  }
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Target</th>
          <th>Verdict</th>
          <th>Signal</th>
        </tr>
      </thead>
      <tbody>
        {tests.slice(0, 15).map((test) => (
          <tr key={test.id}>
            <td>{test.test_type}</td>
            <td className="mono" style={{ fontSize: 11, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {test.target}
            </td>
            <td>{test.result ? <span className="pill">{test.result}</span> : <span className="muted">—</span>}</td>
            <td className="muted" style={{ fontSize: 11, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis' }} title={test.actual_signal ?? test.expected_signal ?? ''}>
              {test.actual_signal ?? test.expected_signal ?? '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AutonomousTab({
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
  const [autoRefresh, setAutoRefresh] = useState(true);

  const status = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/autonomous/status`, AutonomousStatusResponseSchema),
    [engagementId],
  );
  const timeline = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/timeline?limit=200`, TimelineResponseSchema),
    [engagementId],
  );
  const coverage = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/coverage`, CoverageResponseSchema),
    [engagementId],
  );
  const branches = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/branches`, BranchListResponseSchema),
    [engagementId],
  );
  const approvals = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/approvals`, ApprovalListResponseSchema),
    [engagementId],
  );
  const tests = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/tests?limit=200`, TestRegistryResponseSchema),
    [engagementId],
  );
  const ctf = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/ctf`, CtfResponseSchema),
    [engagementId],
  );

  const refreshAll = useCallback(() => {
    status.reload();
    timeline.reload();
    coverage.reload();
    branches.reload();
    approvals.reload();
    tests.reload();
    ctf.reload();
  }, [status, timeline, coverage, branches, approvals, tests, ctf]);

  // Live timeline (§53): periodic refresh while the engine runs.
  useEffect(() => {
    if (!autoRefresh) return;
    const enginePhase = status.data?.engine.phase;
    if (enginePhase && TERMINAL_PHASES.includes(enginePhase)) return;
    const interval = setInterval(() => {
      timeline.reload();
      status.reload();
    }, 3000);
    return () => clearInterval(interval);
  }, [autoRefresh, status, timeline]);

  const control = useCallback(
    async (action: 'start' | 'pause' | 'resume' | 'cancel' | 'replan') => {
      setActionError(null);
      setBusy(action);
      try {
        await apiRequest('POST', `/api/engagements/${engagementId}/autonomous/${action}`, ControlAckSchema, {});
        refreshAll();
      } catch (err) {
        setActionError(err instanceof ApiError ? err.message : 'Unexpected engine control error');
      } finally {
        setBusy(null);
      }
    },
    [engagementId, refreshAll],
  );

  const decideApproval = useCallback(
    async (approval: ApprovalRecord, decision: 'approve' | 'reject') => {
      setActionError(null);
      setBusy(`${decision}:${approval.id}`);
      try {
        await apiRequest('POST', `/api/engagements/${engagementId}/${decision}`, ControlAckSchema, {
          approval_id: approval.id,
        });
        refreshAll();
      } catch (err) {
        setActionError(err instanceof ApiError ? err.message : 'Unexpected approval error');
      } finally {
        setBusy(null);
      }
    },
    [engagementId, refreshAll],
  );

  if (status.loading && !status.data) return <Loading />;
  if (status.error) {
    const error = status.error as unknown as Error & { code?: string };
    const notStarted = error instanceof ApiError && error.code === 'AUTONOMOUS_ENGINE_NOT_STARTED';
    return (
      <div style={{ display: 'grid', gap: 12 }}>
        <ErrorBanner message={error.message} />
        {notStarted && engagementStatus === 'RUNNING' ? (
          <div>
            <button type="button" disabled={busy !== null} onClick={() => control('start')}>
              {busy === 'start' ? 'Starting…' : 'Start autonomous engine'}
            </button>
            <p className="muted">Starts the persistent, restartable loop (§7): recon → model → hypothesize → test → verify → replan.</p>
          </div>
        ) : null}
      </div>
    );
  }

  const engine = status.data as AutonomousStatusResponse;
  const isTerminal = TERMINAL_PHASES.includes(engine.engine.phase);
  const coverageReport: CoverageReport | null = coverage.data?.coverage ?? null;

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      <ErrorBanner message={actionError} />

      <div className="card" style={{ padding: 16, display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        <div>
          <strong>Engine phase</strong>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
            <span className="pill" style={{ fontWeight: 700, color: phaseColor(engine.engine.phase) }}>
              {engine.engine.phase}
            </span>
            <span className="muted">{engine.engine.mode}</span>
          </div>
        </div>
        <div>
          <strong>Cycles / Replans</strong>
          <p style={{ margin: 0 }}>{engine.engine.cycle_count} / {engine.engine.replan_count}</p>
        </div>
        <div style={{ flex: 1, minWidth: 240 }}>
          <strong>Strategy</strong>
          <p className="muted" style={{ margin: 0, fontSize: 12 }}>{engine.engine.strategy_summary ?? '—'}</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {engine.engine.phase === 'CREATED' || !engine.current_run ? (
            <button type="button" disabled={busy !== null || engagementStatus !== 'RUNNING'} onClick={() => control('start')}>
              {busy === 'start' ? 'Starting…' : 'Start'}
            </button>
          ) : null}
          <button type="button" className="secondary" disabled={busy !== null || isTerminal} onClick={() => control('pause')}>
            Pause
          </button>
          <button type="button" className="secondary" disabled={busy !== null || isTerminal} onClick={() => control('resume')}>
            Resume
          </button>
          <button type="button" className="secondary" disabled={busy !== null} onClick={() => control('replan')}>
            Replan
          </button>
          <button type="button" className="secondary" disabled={busy !== null || isTerminal} onClick={() => control('cancel')}>
            Cancel
          </button>
          <label className="muted" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12 }}>
            <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
            live
          </label>
        </div>
        {engine.engine.waiting_reason ? (
          <p className="muted" style={{ margin: 0 }}>waiting: {engine.engine.waiting_reason}</p>
        ) : null}
        {engine.engine.stop_reason ? (
          <p style={{ margin: 0 }}>stopped: <strong>{engine.engine.stop_reason}</strong></p>
        ) : null}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
        <SummaryCounts counts={engine.task_summary} label="Tasks" />
        <SummaryCounts counts={engine.hypothesis_summary} label="Hypotheses" />
        <SummaryCounts counts={engine.finding_summary} label="Findings" />
        <SummaryCounts counts={engine.verification_summary} label="Verifications" />
      </div>

      {coverageReport ? (
        <div className="card" style={{ padding: 12 }}>
          <strong>Coverage (planning signal, §51)</strong>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 6 }}>
            <span className="pill">endpoints {pct(coverageReport.endpoint_coverage)}</span>
            <span className="pill">identities {pct(coverageReport.identity_coverage)}</span>
            <span className="pill">workflows {pct(coverageReport.workflow_coverage)}</span>
            <span className="pill">objects {pct(coverageReport.object_coverage)}</span>
          </div>
          <p className="muted" style={{ fontSize: 11, margin: '6px 0 0' }}>{coverageReport.note}</p>
        </div>
      ) : null}

      {engine.budget ? (
        <div className="card" style={{ padding: 12 }}>
          <strong>Budget usage (§42)</strong>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 6 }}>
            {Object.entries(engine.budget.usage).map(([key, used]) => {
              const limit = (engine.budget?.limits as Record<string, number | null> | null)?.[key] ?? null;
              return (
                <span key={key} className="pill">
                  {key}: {used}
                  {limit !== null ? ` / ${limit}` : ''}
                </span>
              );
            })}
          </div>
        </div>
      ) : null}

      <section>
        <h3>Reasoning branches (§65)</h3>
        {branches.loading && !branches.data ? <Loading /> : <BranchList branches={branches.data?.items ?? []} />}
      </section>

      <section>
        <h3>Experimental registry (§60)</h3>
        {tests.loading && !tests.data ? <Loading /> : <TestRegistry tests={tests.data?.items ?? []} />}
      </section>

      <section>
        <h3>Human approvals (§48)</h3>
        {approvals.loading && !approvals.data ? (
          <Loading />
        ) : (
          <Approvals approvals={approvals.data?.items ?? []} onApprove={(a) => decideApproval(a, 'approve')} onReject={(a) => decideApproval(a, 'reject')} busy={busy} />
        )}
      </section>

      {mode === 'CTF' ? (
        <section>
          <h3>CTF challenge (§4, §29-§31)</h3>
          {ctf.loading && !ctf.data ? (
            <Loading />
          ) : (
            <CtfPanel context={ctf.data?.context ?? null} clues={ctf.data?.clues ?? []} flagConditions={ctf.data?.flag_conditions ?? []} />
          )}
        </section>
      ) : null}

      <section>
        <h3>Live agent timeline (§53)</h3>
        {timeline.loading && !timeline.data ? <Loading /> : <TimelineFeed entries={timeline.data?.timeline.entries ?? []} />}
      </section>
    </div>
  );
}

/** Control endpoint acknowledgements (start/pause/resume/cancel/replan). */
const ControlAckSchema = z.object({}).passthrough();
