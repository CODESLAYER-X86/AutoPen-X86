import type { ReactNode } from 'react';

/** Badge palette — Part 1 engagement statuses plus Part 2 agent statuses. */
const STATUS_CLASS: Record<string, string> = {
  DRAFT: 'badge-gray',
  READY: 'badge-yellow',
  RUNNING: 'badge-green',
  PAUSED: 'badge-yellow',
  COMPLETED: 'badge-purple',
  FAILED: 'badge-red',
  CANCELLED: 'badge-gray',
  // Agent OS statuses (Part 2).
  CREATED: 'badge-gray',
  INITIALIZING: 'badge-yellow',
  WAITING: 'badge-yellow',
  QUEUED: 'badge-yellow',
  PARTIAL: 'badge-purple',
  EXPIRED: 'badge-gray',
  RECOVERY_PENDING: 'badge-red',
  PROPOSED: 'badge-gray',
  ACTIVE: 'badge-green',
  TESTING: 'badge-yellow',
  SUPPORTED: 'badge-green',
  CONFIRMED: 'badge-purple',
  DISPROVED: 'badge-red',
  ABANDONED: 'badge-gray',
  BLOCKED: 'badge-red',
  NEEDS_CONTEXT: 'badge-yellow',
  NEEDS_TOOL: 'badge-yellow',
  NEEDS_IDENTITY: 'badge-yellow',
};

export function StatusBadge({ status }: { status: string }): ReactNode {
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
