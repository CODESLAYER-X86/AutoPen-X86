import type { ReactNode } from 'react';
import { FindingResponseSchema, pageSchema } from '@aegis/contracts';
import { apiRequest } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';

const FindingsPageSchema = pageSchema(FindingResponseSchema);

export function FindingsTab({ engagementId }: { engagementId: string }): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/findings`, FindingsPageSchema),
    [engagementId],
  );

  const confirmed = data?.items.filter((f) => f.status === 'CONFIRMED') ?? [];
  const proposed = data?.items.filter((f) => f.status === 'PROPOSED') ?? [];
  const rejected = data?.items.filter((f) => f.status === 'REJECTED') ?? [];

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
        A hypothesis only becomes a finding after skeptical verification (HYPOTHESIS → TESTING →
        SUPPORTED → VERIFICATION → CONFIRMED). Unverified work never appears here as a finding.
      </p>
      {loading && <Loading label="loading findings" />}
      {error && <ErrorBanner message={error} />}
      {data && data.items.length === 0 && (
        <EmptyState>
          No findings yet. Confirmed findings appear here once the agent verifies a hypothesis.
        </EmptyState>
      )}

      {confirmed.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Confirmed ({confirmed.length})</h4>
          <table className="table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Hypothesis</th>
                <th>Evidence</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {confirmed.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 420 }}>{f.title}</td>
                  <td>{f.severity}</td>
                  <td className="mono">{f.hypothesis_id ?? '—'}</td>
                  <td>{f.evidence_ids.length}</td>
                  <td>{f.updated_at.slice(0, 19).replace('T', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {proposed.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Proposed / awaiting verification ({proposed.length})</h4>
          <table className="table">
            <tbody>
              {proposed.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 520 }}>{f.title}</td>
                  <td>{f.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {rejected.length > 0 && (
        <>
          <h4 style={{ margin: '16px 0 4px' }}>Rejected (false positives, {rejected.length})</h4>
          <table className="table">
            <tbody>
              {rejected.map((f) => (
                <tr key={f.id}>
                  <td style={{ maxWidth: 520 }}>{f.title}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
