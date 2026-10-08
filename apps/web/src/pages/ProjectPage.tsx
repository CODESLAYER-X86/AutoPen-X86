import { useState, type FormEvent, type ReactNode } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  CreateEngagementRequestSchema,
  EngagementSchema,
  ProjectSchema,
  pageSchema,
  type Engagement,
} from '@aegis/contracts';
import { ENGAGEMENT_MODES } from '@aegis/shared';
import { apiRequest, ApiError } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { ErrorBanner, Loading, SuccessBanner } from '../components/Feedback.js';
import { StatusBadge, ModeBadge } from '../components/StatusBadge.js';

const EngagementsPageSchema = pageSchema(EngagementSchema);

export function ProjectPage(): ReactNode {
  const { projectId } = useParams<{ projectId: string }>();
  const project = useResource(
    () => apiRequest('GET', `/api/projects/${projectId}`, ProjectSchema),
    [projectId],
  );
  const engagements = useResource(
    () => apiRequest('GET', `/api/projects/${projectId}/engagements`, EngagementsPageSchema),
    [projectId],
  );

  const [name, setName] = useState('');
  const [mode, setMode] = useState<'PENTEST' | 'CTF'>('PENTEST');
  const [description, setDescription] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    setSuccess(null);
    setBusy(true);
    try {
      const body = CreateEngagementRequestSchema.parse({
        project_id: projectId,
        name,
        mode,
        description: description || undefined,
      });
      const engagement = await apiRequest('POST', '/api/engagements', EngagementSchema, body);
      setSuccess(`Engagement '${engagement.name}' created as ${engagement.status}`);
      setName('');
      setDescription('');
      engagements.reload();
    } catch (err) {
      setFormError(
        err instanceof ApiError
          ? `${err.message}${err.details ? `\n${JSON.stringify(err.details)}` : ''}`
          : 'Unexpected error while creating the engagement',
      );
    } finally {
      setBusy(false);
    }
  };

  if (project.error) {
    return (
      <div>
        <h1 className="page-title">Project</h1>
        <ErrorBanner message={project.error} />
        <Link to="/projects">← back to projects</Link>
      </div>
    );
  }

  return (
    <div>
      {project.data && (
        <>
          <h1 className="page-title">{project.data.name}</h1>
          <p className="page-subtitle">{project.data.description || 'No description'}</p>
        </>
      )}
      {project.loading && <Loading label="loading project" />}

      <div className="grid grid-2">
        <div className="card">
          <div className="card-title">Create engagement</div>
          <form className="form" onSubmit={onCreate}>
            <label className="field">
              Name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                minLength={1}
                maxLength={200}
                placeholder="Q4 web app assessment"
              />
            </label>
            <label className="field">
              Mode
              <select value={mode} onChange={(e) => setMode(e.target.value as 'PENTEST' | 'CTF')}>
                {ENGAGEMENT_MODES.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              Description / rules of engagement
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={4000}
                placeholder="Authorization reference, time window, constraints (optional)"
              />
            </label>
            <ErrorBanner message={formError} />
            <SuccessBanner message={success} />
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create engagement'}
            </button>
          </form>
        </div>

        <div className="card">
          <div className="card-title">
            Engagements {engagements.data ? `(${engagements.data.total})` : ''}
          </div>
          {engagements.loading && <Loading label="loading engagements" />}
          {engagements.error && <ErrorBanner message={engagements.error} />}
          {engagements.data && engagements.data.items.length === 0 && (
            <div className="empty-state">No engagements in this project yet.</div>
          )}
          {engagements.data && engagements.data.items.length > 0 && (
            <table className="data">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Mode</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {engagements.data.items.map((engagement: Engagement) => (
                  <tr key={engagement.id}>
                    <td>
                      <Link to={`/engagements/${engagement.id}`}>{engagement.name}</Link>
                    </td>
                    <td>
                      <ModeBadge mode={engagement.mode} />
                    </td>
                    <td>
                      <StatusBadge status={engagement.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
