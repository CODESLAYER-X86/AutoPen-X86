import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

export function NotFoundPage(): ReactNode {
  return (
    <div>
      <h1 className="page-title">Not found</h1>
      <div className="empty-state">
        This page does not exist. <Link to="/">Return to the dashboard</Link>.
      </div>
    </div>
  );
}
