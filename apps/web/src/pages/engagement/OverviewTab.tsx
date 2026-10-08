import type { ReactNode } from 'react';
import type { Engagement, EngagementReadiness } from '@aegis/contracts';

export function OverviewTab({
  engagement,
  readiness,
}: {
  engagement: Engagement;
  readiness: EngagementReadiness;
}): ReactNode {
  return (
    <div className="grid grid-2">
      <div className="card">
        <div className="card-title">Details</div>
        <dl className="kv">
          <dt>Engagement ID</dt>
          <dd>{engagement.id}</dd>
          <dt>Project</dt>
          <dd>{engagement.project_id}</dd>
          <dt>Mode</dt>
          <dd>{engagement.mode}</dd>
          <dt>Status</dt>
          <dd>{engagement.status}</dd>
          <dt>Created</dt>
          <dd>{engagement.created_at}</dd>
          <dt>Started</dt>
          <dd>{engagement.started_at ?? '—'}</dd>
          <dt>Completed</dt>
          <dd>{engagement.completed_at ?? '—'}</dd>
        </dl>
      </div>

      <div className="card">
        <div className="card-title">Readiness</div>
        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 13, lineHeight: 2 }}>
          <li>{readiness.has_scope ? '✓' : '✗'} Scope configured</li>
          <li>{readiness.has_targets ? '✓' : '✗'} At least one in-scope target</li>
          <li>
            {readiness.ready ? '✓' : '✗'} Ready to start (
            {engagement.status === 'DRAFT' ? 'will auto-promote to READY' : 'preconditions checked'})
          </li>
        </ul>
        {!readiness.ready && (
          <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 12 }}>
            An engagement cannot be started until a scope exists and at least one target inside
            that scope has been added.
          </p>
        )}
      </div>

      <div className="card">
        <div className="card-title">Lifecycle</div>
        <div className="mono" style={{ fontSize: 12, lineHeight: 1.8 }}>
          DRAFT → READY → RUNNING ⇄ PAUSED → COMPLETED / FAILED / CANCELLED
          <br />
          Invalid transitions are rejected deterministically by the server (never by a model).
        </div>
      </div>
    </div>
  );
}
