import type { ReactNode } from 'react';
import type { EngagementStatus } from '@aegis/shared';

const STATUS_CLASS: Record<EngagementStatus, string> = {
  DRAFT: 'badge-gray',
  READY: 'badge-yellow',
  RUNNING: 'badge-green',
  PAUSED: 'badge-yellow',
  COMPLETED: 'badge-purple',
  FAILED: 'badge-red',
  CANCELLED: 'badge-gray',
};

export function StatusBadge({ status }: { status: EngagementStatus }): ReactNode {
  return <span className={`badge ${STATUS_CLASS[status] ?? 'badge-gray'}`}>{status}</span>;
}

export function ModeBadge({ mode }: { mode: string }): ReactNode {
  return (
    <span className={`badge ${mode === 'CTF' ? 'badge-purple' : 'badge-green'}`}>{mode}</span>
  );
}

export function TypeBadge({ type }: { type: string }): ReactNode {
  return <span className="badge badge-gray">{type}</span>;
}
