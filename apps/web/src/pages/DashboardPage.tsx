import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { MetaResponseSchema, ProjectSchema, pageSchema, type Project } from '@aegis/contracts';
import { apiRequest } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { useAuth } from '../auth/AuthContext.js';
import { ErrorBanner, Loading } from '../components/Feedback.js';

const ProjectsPageSchema = pageSchema(ProjectSchema);

export function DashboardPage(): ReactNode {
  const { user } = useAuth();
  const meta = useResource(() => apiRequest('GET', '/api/meta', MetaResponseSchema), []);
  const projects = useResource(
    () => apiRequest('GET', '/api/projects', ProjectsPageSchema),
    [],
  );

  return (
    <div>
      <h1 className="page-title">Dashboard</h1>
      <p className="page-subtitle">
        Signed in as {user?.name} ({user?.email})
      </p>

      {meta.error && <ErrorBanner message={meta.error} />}
      {meta.loading && <Loading label="loading platform status" />}
      {meta.data && (
        <>
          <div className="grid grid-3">
            <div className="card">
              <div className="stat-value">{meta.data.models.strategic.provider}</div>
              <div className="stat-label">
                Strategic model ({meta.data.models.strategic.model_id})
              </div>
            </div>
            <div className="card">
              <div className="stat-value">{meta.data.models.tactical.provider}</div>
              <div className="stat-label">Tactical model ({meta.data.models.tactical.model_id})</div>
            </div>
            <div className="card">
              <div className="stat-value">
                {meta.data.capabilities.tools_implemented}/{meta.data.capabilities.tools_total}
              </div>
              <div className="stat-label">Tools implemented / registered</div>
            </div>
          </div>

          <div className="card">
            <div className="card-title">Subsystem status (Part 1 foundation)</div>
            <ul style={{ margin: 0, paddingLeft: 20, fontSize: 13, lineHeight: 1.9 }}>
              <li>Engagement lifecycle &amp; deterministic scope enforcement — implemented</li>
              <li>HTTP worker — {meta.data.features.tools_http ? 'enabled' : 'not implemented (Part 3)'}</li>
              <li>Browser worker — {meta.data.features.tools_browser ? 'enabled' : 'not implemented (Part 4)'}</li>
              <li>Knowledge search — {meta.data.features.knowledge_search ? 'enabled' : 'not implemented (Part 5)'}</li>
              <li>Reporting — {meta.data.features.reporting ? 'enabled' : 'not implemented (Part 6+)'}</li>
              <li>
                Autonomous run loop —{' '}
                {meta.data.capabilities.autonomous_run_loop ? 'running' : 'not implemented (Part 2)'}
              </li>
            </ul>
          </div>
        </>
      )}

      <div className="card">
        <div className="card-title">
          Projects {projects.data ? `(${projects.data.total})` : ''}
        </div>
        {projects.loading && <Loading label="loading projects" />}
        {projects.error && <ErrorBanner message={projects.error} />}
        {projects.data && projects.data.items.length === 0 && (
          <div className="empty-state">
            No projects yet. Create your first project to start an engagement.
          </div>
        )}
        {projects.data && projects.data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.items.slice(0, 5).map((project: Project) => (
                <tr key={project.id}>
                  <td>
                    <Link to={`/projects/${project.id}`}>{project.name}</Link>
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{project.description}</td>
                  <td className="mono">{project.created_at.slice(0, 19).replace('T', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="card-title">Next steps</div>
        <ol style={{ margin: 0, paddingLeft: 20, fontSize: 13, lineHeight: 1.9 }}>
          <li>
            Create a <Link to="/projects">project</Link> for your authorised testing work
          </li>
          <li>Create an engagement (PENTEST or CTF mode)</li>
          <li>Configure the engagement scope — only in-scope hosts can ever be contacted</li>
          <li>Add a target; the platform rejects anything outside scope</li>
        </ol>
      </div>
    </div>
  );
}
