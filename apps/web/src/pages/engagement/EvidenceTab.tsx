import type { ReactNode } from 'react';
import { EvidenceSchema, pageSchema, type Evidence } from '@aegis/contracts';
import { apiRequest } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';

const EvidencePageSchema = pageSchema(EvidenceSchema);

export function EvidenceTab({ engagementId }: { engagementId: string }): ReactNode {
  const { data, error, loading } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/evidence`, EvidencePageSchema),
    [engagementId],
  );

  return (
    <div className="card">
      <div className="card-title">Evidence {data ? `(${data.total})` : ''}</div>
      {loading && <Loading label="loading evidence" />}
      {error && <ErrorBanner message={error} />}
      {data && data.items.length === 0 && (
        <EmptyState>
          No evidence captured yet. Evidence is produced by the HTTP engine, browser
          service and workers (Part 3 interaction layer); the immutable, hash-addressed evidence store behind this list is
          already implemented.
        </EmptyState>
      )}
      {data && data.items.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>Type</th>
              <th>Source</th>
              <th>SHA-256</th>
              <th>Parent</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((record: Evidence) => (
              <tr key={record.id}>
                <td>{record.type}</td>
                <td>{record.source}</td>
                <td className="mono" title={record.sha256}>
                  {record.sha256.slice(0, 16)}…
                </td>
                <td className="mono">{record.parent_id ?? '—'}</td>
                <td className="mono">{record.created_at.slice(0, 19).replace('T', ' ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
