import type { ReactNode } from 'react';
import { useState } from 'react';
import { z } from 'zod';
import { pageSchema, FindingDetailResponseSchema } from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';
import { StatusBadge } from '../../components/StatusBadge.js';

const FindingsPageSchema = pageSchema(FindingDetailResponseSchema);

const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: 'text-danger',
  HIGH: 'text-danger',
  MEDIUM: 'text-warn',
  LOW: 'text-muted',
};

export function FindingsTab({ engagementId }: { engagementId: string }): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/findings`, FindingsPageSchema),
    [engagementId],
  );
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNote, setActionNote] = useState<string | null>(null);

  const act = async (findingId: string, action: 'verify' | 'accept' | 'reject' | 'retest'): Promise<void> => {
    setBusyId(findingId);
    setActionError(null);
    setActionNote(null);
    try {
      if (action === 'verify') {
        const result = await apiRequest(
          'POST',
          `/api/engagements/${engagementId}/findings/${findingId}/verify`,
          z.any(),
          {},
        );
        const verdict = (result as { verification?: { status?: string; confidence?: number } }).verification;
        setActionNote(
          `Verification verdict: ${verdict?.status ?? 'unknown'} (confidence ${verdict?.confidence ?? 'n/a'}).`,
        );
      } else if (action === 'accept' || action === 'reject') {
        await apiRequest(
          'POST',
          `/api/engagements/${engagementId}/findings/${findingId}/review`,
          z.any(),
          {
            decision: action === 'accept' ? 'ACCEPT' : 'REJECT',
            reason: action === 'accept' ? 'human accepted the finding' : 'human rejected the finding',
          },
        );
        setActionNote(`Finding ${action}ed by human review (§67).`);
      } else {
        await apiRequest('POST', `/api/engagements/${engagementId}/findings/${findingId}/retest`, z.any(), {
          note: 'retest requested from the findings view',
        });
        setActionNote('Retest requested (§37): the security property will be re-verified.');
      }
      reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusyId(null);
    }
  };

  const verified = data?.items.filter((f) => f.status === 'VERIFIED' || f.status === 'ACCEPTED') ?? [];
  const pipeline =
    data?.items.filter(
      (f) =>
        f.status === 'CANDIDATE' ||
        f.status === 'UNDER_REVIEW' ||
        f.status === 'VERIFICATION_PENDING' ||
        f.status === 'VERIFYING' ||
        f.status === 'INCONCLUSIVE' ||
        f.status === 'PROPOSED' ||
        f.status === 'CONFIRMED',
    ) ?? [];
  const rejected = data?.items.filter((f) => f.status === 'REJECTED' || f.status === 'DUPLICATE') ?? [];

  return (
    <div className="card">
      <div className="toolbar">
        <div className="card-title" style={{ margin: 0, border: 'none' }}>
          Findings {data ? `(${data.total})` : ''}
        </div>
        <button type="button" className="btn btn-small" onClick={reload}>
          Refresh
        </button>
      </div>
      <p className="page-subtitle">
        Lifecycle (§4-§5): CANDIDATE → UNDER_REVIEW → VERIFICATION_PENDING → VERIFYING → VERIFIED,
        with honest alternatives (INCONCLUSIVE / REJECTED / DUPLICATE). Confidence is NOT severity
        (§16); rejected findings are kept as false-positive data.
      </p>
      {actionNote && <p className="text-muted">{actionNote}</p>}
      {actionError && <ErrorBanner message={actionError} />}
      {loading && <Loading label="loading findings" />}
      {error && <ErrorBanner message={error} />}
      {data && data.items.length === 0 && (
        <EmptyState>No findings yet. Candidate findings appear once the engine records signals.</EmptyState>
      )}

      {verified.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Verified / accepted ({verified.length})</h4>
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Severity / CVSS</th>
                <th>Confidence</th>
                <th>Endpoints</th>
                <th>Retest</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {verified.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 320 }}>{f.title}</td>
                  <td>
                    <StatusBadge status={f.status} />
                  </td>
                  <td>
                    <span className={SEVERITY_CLASS[f.severity] ?? ''}>{f.severity}</span>
                    {f.cvss ? (
                      <div className="mono text-muted" style={{ fontSize: '0.75rem' }}>
                        {f.cvss.base_score} {f.cvss.vector.slice(0, 34)}…
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {f.confidence !== null && f.confidence !== undefined
                      ? `${f.confidence.toFixed(2)} (${f.confidence_level ?? '—'})`
                      : '—'}
                  </td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>
                    {(f.affected_endpoints ?? []).slice(0, 2).join(', ') || '—'}
                  </td>
                  <td>{f.retest_state ?? 'NOT_RETESTED'}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-small"
                      disabled={busyId === f.id}
                      onClick={() => act(f.id, 'retest')}
                    >
                      Retest
                    </button>{' '}
                    <button
                      type="button"
                      className="btn btn-small"
                      disabled={busyId === f.id}
                      onClick={() => act(f.id, 'reject')}
                    >
                      Reject
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {pipeline.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>In the verification pipeline ({pipeline.length})</h4>
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Observed</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {pipeline.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 300 }}>{f.title}</td>
                  <td>
                    <StatusBadge status={f.status} />
                  </td>
                  <td>{f.severity}</td>
                  <td>{f.category ?? '—'}</td>
                  <td style={{ maxWidth: 260, fontSize: '0.8rem' }}>
                    {(f.observed_behavior ?? f.description).slice(0, 120)}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-small"
                      disabled={busyId === f.id}
                      onClick={() => act(f.id, 'verify')}
                    >
                      {busyId === f.id ? 'Verifying…' : 'Verify'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {rejected.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Rejected / duplicates (kept for evaluation, {rejected.length})</h4>
          <table className="table">
            <tbody>
              {rejected.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 420 }}>
                    {f.title}
                    {f.duplicate_of ? <span className="text-muted"> (dup of {f.duplicate_of.slice(0, 12)}…)</span> : null}
                  </td>
                  <td>
                    <StatusBadge status={f.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
