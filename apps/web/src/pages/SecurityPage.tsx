/**
 * Part 8 — Security & Operations console (spec Part 8 §49, §89, §94-§96, §111):
 * emergency stop, security event timeline, incidents, circuit breakers and
 * audit-chain integrity — the human control surface for the platform.
 */
import type { ReactNode } from 'react';
import { useCallback, useEffect, useState } from 'react';
import { z } from 'zod';
import { SecurityEventRecordSchema, IncidentRecordSchema } from '@aegis/contracts';
import { apiRequest } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../components/Feedback.js';
import { StatusBadge } from '../components/StatusBadge.js';

const EventsSchema = z.object({ items: z.array(SecurityEventRecordSchema) });
const IncidentsSchema = z.object({ items: z.array(IncidentRecordSchema) });
const BreakersSchema = z.object({
  items: z.array(
    z.object({
      id: z.string(),
      subject: z.string(),
      subject_id: z.string(),
      category: z.string(),
      state: z.string(),
      violation_count: z.number(),
      threshold: z.number(),
    }),
  ),
});
const StopSchema = z.object({
  status: z.string(),
  engaged_at: z.string().nullable(),
  released_at: z.string().nullable(),
  reason: z.string().nullable(),
  cancelled_tasks: z.number(),
  revoked_grants: z.number(),
});
const MetricsSchema = z.object({
  scope_denials: z.number(),
  prompt_injection_events: z.number(),
  open_circuit_breakers: z.number(),
  open_incidents: z.number(),
  emergency_stop_engaged: z.boolean(),
  pending_outbox_events: z.number(),
});
const ChainSchema = z.object({
  verified: z.boolean(),
  records_checked: z.number(),
  reason: z.string().nullable(),
});

function severityColor(severity: string): string {
  if (severity === 'CRITICAL') return 'var(--status-critical, #e5484d)';
  if (severity === 'HIGH') return 'var(--status-error, #e5484d)';
  if (severity === 'MEDIUM') return 'var(--status-warning, #f5a524)';
  return 'var(--status-info)';
}

export function SecurityPage(): ReactNode {
  const events = useResource(() => apiRequest('GET', '/api/security/events?limit=50', EventsSchema), []);
  const incidents = useResource(() => apiRequest('GET', '/api/security/incidents', IncidentsSchema), []);
  const breakers = useResource(() => apiRequest('GET', '/api/security/breakers', BreakersSchema), []);
  const metrics = useResource(() => apiRequest('GET', '/api/metrics', MetricsSchema), []);
  const [stop, setStop] = useState<z.infer<typeof StopSchema> | null>(null);
  const [chain, setChain] = useState<z.infer<typeof ChainSchema> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshStop = useCallback(async () => {
    try {
      setStop(await apiRequest('GET', '/api/security/emergency-stop', StopSchema));
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    void refreshStop();
  }, [refreshStop]);

  const act = async (action: 'engage' | 'release') => {
    setBusy(true);
    setError(null);
    try {
      const reason = action === 'engage' ? window.prompt('Emergency stop reason:') ?? '' : '';
      if (action === 'engage' && reason.length === 0) return;
      const response = await apiRequest(
        'POST',
        `/api/security/emergency-stop/${action}`,
        StopSchema,
        action === 'engage' ? { reason } : {},
      );
      setStop(response);
      await Promise.all([events.reload(), incidents.reload(), metrics.reload()]);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verifyChain = async () => {
    setBusy(true);
    setError(null);
    try {
      setChain(await apiRequest('POST', '/api/audit-chain/verify', ChainSchema, {}));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Security &amp; Operations</h1>
      <p className="page-subtitle">
        Part 8 controls: the emergency stop is deterministic and never depends on the model;
        scope denials and injections raise security events; the audit log is tamper-evident.
      </p>

      {error && <ErrorBanner message={error} />}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-title">Emergency stop (§89)</div>
          {stop ? (
            <>
              <dl className="kv">
                <dt>Status</dt>
                <dd>
                  <StatusBadge status={stop.status} />
                </dd>
                <dt>Reason</dt>
                <dd>{stop.reason ?? '—'}</dd>
                <dt>Cancelled tasks</dt>
                <dd>{stop.cancelled_tasks}</dd>
                <dt>Revoked grants</dt>
                <dd>{stop.revoked_grants}</dd>
              </dl>
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                {stop.status !== 'ENGAGED' ? (
                  <button disabled={busy} onClick={() => void act('engage')} className="btn btn-danger">
                    Engage emergency stop
                  </button>
                ) : (
                  <button disabled={busy} onClick={() => void act('release')}>
                    Release stop
                  </button>
                )}
              </div>
            </>
          ) : (
            <Loading label="loading stop state" />
          )}
        </div>

        <div className="card">
          <div className="card-title">Security metrics (24h, §49)</div>
          {metrics.data ? (
            <dl className="kv">
              <dt>Scope denials</dt>
              <dd>{metrics.data.scope_denials}</dd>
              <dt>Prompt-injection events</dt>
              <dd>{metrics.data.prompt_injection_events}</dd>
              <dt>Open circuit breakers</dt>
              <dd>{metrics.data.open_circuit_breakers}</dd>
              <dt>Open incidents</dt>
              <dd>{metrics.data.open_incidents}</dd>
              <dt>Pending outbox events</dt>
              <dd>{metrics.data.pending_outbox_events}</dd>
            </dl>
          ) : metrics.error ? (
            <ErrorBanner message={metrics.error} />
          ) : (
            <Loading label="loading metrics" />
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Audit chain integrity (§85)</div>
        <button type="button" className="btn" disabled={busy} onClick={() => void verifyChain()}>
          Verify tamper-evidence
        </button>
        {chain && (
          <p style={{ marginTop: 10, color: chain.verified ? 'var(--status-ok)' : 'var(--status-error)' }}>
            {chain.verified
              ? `Chain verified — ${chain.records_checked} records, no tampering detected.`
              : `CHAIN BROKEN: ${chain.reason ?? 'unknown reason'}`}
          </p>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Open incidents (§94-§96)</div>
        {incidents.error && <ErrorBanner message={incidents.error} />}
        {incidents.loading && <Loading label="loading incidents" />}
        {incidents.data && incidents.data.items.length === 0 && (
          <EmptyState>no open incidents</EmptyState>
        )}
        {incidents.data && incidents.data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Events</th>
                <th>Opened</th>
              </tr>
            </thead>
            <tbody>
              {incidents.data.items.map((incident) => (
                <tr key={incident.id}>
                  <td title={incident.id}>{incident.title.slice(0, 60)}</td>
                  <td style={{ color: severityColor(incident.severity) }}>{incident.severity}</td>
                  <td>{incident.status}</td>
                  <td>{incident.event_count}</td>
                  <td>{incident.opened_at.slice(0, 19).replace('T', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Circuit breakers (§97-§99)</div>
        {breakers.error && <ErrorBanner message={breakers.error} />}
        {breakers.loading && <Loading label="loading breakers" />}
        {breakers.data && breakers.data.items.length === 0 && <EmptyState>all breakers closed</EmptyState>}
        {breakers.data && breakers.data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Subject</th>
                <th>Category</th>
                <th>State</th>
                <th>Violations</th>
              </tr>
            </thead>
            <tbody>
              {breakers.data.items.map((breaker) => (
                <tr key={breaker.id}>
                  <td>
                    {breaker.subject} · {breaker.subject_id.slice(0, 14)}…
                  </td>
                  <td>{breaker.category}</td>
                  <td>{breaker.state}</td>
                  <td>
                    {breaker.violation_count}/{breaker.threshold}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-title">Security event timeline (§96)</div>
        {events.error && <ErrorBanner message={events.error} />}
        {events.loading && <Loading label="loading events" />}
        {events.data && events.data.items.length === 0 && <EmptyState>no security events</EmptyState>}
        {events.data && events.data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Actor</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {events.data.items.map((event) => (
                <tr key={event.id}>
                  <td>{event.created_at.slice(0, 19).replace('T', ' ')}</td>
                  <td style={{ color: severityColor(event.severity) }}>{event.severity}</td>
                  <td>{event.category}</td>
                  <td>{event.actor}</td>
                  <td>{event.description.slice(0, 90)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
