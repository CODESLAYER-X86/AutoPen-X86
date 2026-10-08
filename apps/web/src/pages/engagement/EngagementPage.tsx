import { useCallback, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import { EngagementDetailSchema, EngagementSchema, type Engagement } from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading } from '../../components/Feedback.js';
import { StatusBadge, ModeBadge } from '../../components/StatusBadge.js';
import { OverviewTab } from './OverviewTab.js';
import { TargetsTab } from './TargetsTab.js';
import { ScopeTab } from './ScopeTab.js';
import { IdentitiesTab } from './IdentitiesTab.js';
import { ActivityTab } from './ActivityTab.js';
import { EvidenceTab } from './EvidenceTab.js';
import { FindingsTab } from './FindingsTab.js';

const TABS = [
  'overview',
  'targets',
  'scope',
  'identities',
  'activity',
  'evidence',
  'findings',
] as const;
type Tab = (typeof TABS)[number];

export function EngagementPage(): ReactNode {
  const { engagementId } = useParams<{ engagementId: string }>();
  const [tab, setTab] = useState<Tab>('overview');
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const detail = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}`, EngagementDetailSchema),
    [engagementId],
  );

  const lifecycle = useCallback(
    async (action: 'start' | 'pause' | 'resume' | 'cancel') => {
      if (!engagementId) return;
      setActionError(null);
      setBusyAction(action);
      try {
        await apiRequest('POST', `/api/engagements/${engagementId}/${action}`, EngagementSchema);
        detail.reload();
      } catch (err) {
        setActionError(
          err instanceof ApiError
            ? `${err.message}${err.details ? `\n${JSON.stringify(err.details)}` : ''}`
            : 'Unexpected lifecycle error',
        );
      } finally {
        setBusyAction(null);
      }
    },
    [engagementId, detail],
  );

  if (detail.loading) {
    return <Loading label="loading engagement" />;
  }
  if (detail.error || !detail.data) {
    return (
      <div>
        <h1 className="page-title">Engagement</h1>
        <ErrorBanner message={detail.error ?? 'Engagement not found'} />
        <Link to="/projects">← back to projects</Link>
      </div>
    );
  }

  const { engagement, readiness } = detail.data;
  const status = engagement.status;

  return (
    <div>
      <div className="toolbar">
        <div>
          <h1 className="page-title" style={{ display: 'inline' }}>
            {engagement.name}
          </h1>{' '}
          <ModeBadge mode={engagement.mode} /> <StatusBadge status={status} />
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            {engagement.description || 'No description'}
          </p>
        </div>
        <div className="actions-row" style={{ margin: 0 }}>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busyAction !== null || status !== 'READY'}
            onClick={() => void lifecycle('start')}
          >
            {busyAction === 'start' ? 'Starting…' : 'Start'}
          </button>
          <button
            type="button"
            className="btn"
            disabled={busyAction !== null || status !== 'RUNNING'}
            onClick={() => void lifecycle('pause')}
          >
            Pause
          </button>
          <button
            type="button"
            className="btn"
            disabled={busyAction !== null || status !== 'PAUSED'}
            onClick={() => void lifecycle('resume')}
          >
            Resume
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={busyAction !== null || ['COMPLETED', 'FAILED', 'CANCELLED'].includes(status)}
            onClick={() => void lifecycle('cancel')}
          >
            Cancel
          </button>
        </div>
      </div>

      {status === 'RUNNING' && (
        <div className="notice" style={{ marginBottom: 16 }}>
          <h4>Status: RUNNING — autonomous loop not implemented</h4>
          <p>
            The lifecycle state is RUNNING, but the autonomous execution loop (strategic model,
            tasks, workers) is scheduled for Part 2. No target interaction is happening.
          </p>
        </div>
      )}

      <ErrorBanner message={actionError} />

      <div className="tabs">
        {TABS.map((name) => (
          <button
            key={name}
            type="button"
            className={tab === name ? 'tab active' : 'tab'}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>

      {tab === 'overview' && <OverviewTab engagement={engagement} readiness={readiness} />}
      {tab === 'targets' && <TargetsTab engagementId={engagement.id} onChanged={detail.reload} />}
      {tab === 'scope' && <ScopeTab engagementId={engagement.id} onChanged={detail.reload} />}
      {tab === 'identities' && <IdentitiesTab engagementId={engagement.id} />}
      {tab === 'activity' && <ActivityTab engagementId={engagement.id} />}
      {tab === 'evidence' && <EvidenceTab engagementId={engagement.id} />}
      {tab === 'findings' && <FindingsTab />}

      <p style={{ marginTop: 24 }}>
        <span className="mono" style={{ color: 'var(--text-muted)' }}>
          {engagement.id}
        </span>
      </p>
    </div>
  );
}
