import type { ReactNode } from 'react';
import { EngagementEventSchema, pageSchema, type EngagementEvent } from '@aegis/contracts';
import { apiRequest } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';

const EventsPageSchema = pageSchema(EngagementEventSchema);

function payloadPreview(payload: Record<string, unknown>): string {
  const text = JSON.stringify(payload);
  return text === '{}' ? '' : text.length > 160 ? `${text.slice(0, 160)}…` : text;
}

export function ActivityTab({ engagementId }: { engagementId: string }): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/events?limit=200`, EventsPageSchema),
    [engagementId],
  );

  return (
    <div className="card">
      <div className="toolbar">
        <div className="card-title" style={{ margin: 0, border: 'none' }}>
          Event stream {data ? `(${data.total})` : ''}
        </div>
        <button type="button" className="btn btn-small" onClick={reload}>
          Refresh
        </button>
      </div>
      {loading && <Loading label="loading events" />}
      {error && <ErrorBanner message={error} />}
      {data && data.items.length === 0 && <EmptyState>No events recorded yet.</EmptyState>}
      {data && data.items.length > 0 && (
        <div>
          {data.items.map((event: EngagementEvent) => (
            <div className="timeline-item" key={event.id}>
              <div className="timeline-type">{event.type}</div>
              <div className="timeline-time">
                {event.occurred_at.slice(0, 23).replace('T', ' ')}
                {event.trace_id ? ` · trace ${event.trace_id}` : ''}
              </div>
              {payloadPreview(event.payload) && (
                <div className="timeline-payload">{payloadPreview(event.payload)}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
