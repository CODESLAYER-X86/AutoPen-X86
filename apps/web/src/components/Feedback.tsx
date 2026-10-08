import type { ReactNode } from 'react';

export function ErrorBanner({ message }: { message: string | null }): ReactNode {
  if (!message) return null;
  return <div className="error-banner">{message}</div>;
}

export function SuccessBanner({ message }: { message: string | null }): ReactNode {
  if (!message) return null;
  return <div className="success-banner">{message}</div>;
}

export function Loading({ label = 'loading' }: { label?: string }): ReactNode {
  return <div className="loading">{label}…</div>;
}

export function EmptyState({ children }: { children: ReactNode }): ReactNode {
  return <div className="empty-state">{children}</div>;
}

/**
 * Explicit "not implemented" state (spec: final instruction — never fake
 * functionality; surface the planned part instead).
 */
export function NotImplemented({
  title,
  plannedPart,
  description,
}: {
  title: string;
  plannedPart: string;
  description: string;
}): ReactNode {
  return (
    <div className="notice">
      <h4>{title} — not implemented in Part 1</h4>
      <p>
        {description} Planned for <strong>{plannedPart}</strong>. Interfaces for this subsystem are
        already registered (see Settings → Tools), and calling them returns an explicit
        NOT_IMPLEMENTED error rather than pretending to work.
      </p>
    </div>
  );
}
