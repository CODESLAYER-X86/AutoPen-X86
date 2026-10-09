import { createBrowserRouter, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth/AuthContext.js';
import { Layout } from './components/Layout.js';
import { LoginPage } from './pages/LoginPage.js';
import { DashboardPage } from './pages/DashboardPage.js';
import { ProjectsPage } from './pages/ProjectsPage.js';
import { ProjectPage } from './pages/ProjectPage.js';
import { EngagementPage } from './pages/engagement/EngagementPage.js';
import { SettingsPage } from './pages/SettingsPage.js';
import { EvaluationsPage } from './pages/EvaluationsPage.js';
import { NotFoundPage } from './pages/NotFoundPage.js';
import type { ReactNode } from 'react';

function Protected({ children }: { children: ReactNode }): ReactNode {
  const { user, ready } = useAuth();
  if (!ready) return <div className="loading">initialising…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  {
    element: (
      <AuthProvider>
        <Protected>
          <Layout />
        </Protected>
      </AuthProvider>
    ),
    children: [
      { path: '/', element: <DashboardPage /> },
      { path: '/projects', element: <ProjectsPage /> },
      { path: '/projects/:projectId', element: <ProjectPage /> },
      { path: '/engagements/:engagementId', element: <EngagementPage /> },
      { path: '/evaluations', element: <EvaluationsPage /> },
      { path: '/settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
]);

export const AppRouter = router;
