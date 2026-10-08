import { useState, type FormEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { CreateProjectRequestSchema, ProjectSchema, pageSchema, type Project } from '@aegis/contracts';
import { apiRequest, ApiError } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { ErrorBanner, Loading, SuccessBanner } from '../components/Feedback.js';

const ProjectsPageSchema = pageSchema(ProjectSchema);

export function ProjectsPage(): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', '/api/projects', ProjectsPageSchema),
    [],
  );
  const [name, setName] = useState('');
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
      const body = CreateProjectRequestSchema.parse({
        name,
        description: description || undefined,
      });
      const project = await apiRequest('POST', '/api/projects', ProjectSchema, body);
      setSuccess(`Project '${project.name}' created`);
      setName('');
      setDescription('');
      reload();
    } catch (err) {
      setFormError(
        err instanceof ApiError
          ? `${err.message}${err.details ? `\n${JSON.stringify(err.details)}` : ''}`
          : 'Unexpected error while creating the project',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="page-title">Projects</h1>
      <p className="page-subtitle">Groups of engagements under one owner</p>

      <div className="grid grid-2">
        <div className="card">
          <div className="card-title">Create project</div>
          <form className="form" onSubmit={onCreate}>
            <label className="field">
              Name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                minLength={1}
                maxLength={200}
              />
            </label>
            <label className="field">
              Description
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={2000}
                placeholder="Context for this body of work (optional)"
              />
            </label>
            <ErrorBanner message={formError} />
            <SuccessBanner message={success} />
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Creating…' : 'Create project'}
            </button>
          </form>
        </div>

        <div className="card">
          <div className="card-title">Existing projects {data ? `(${data.total})` : ''}</div>
          {loading && <Loading label="loading projects" />}
          {error && <ErrorBanner message={error} />}
          {data && data.items.length === 0 && (
            <div className="empty-state">No projects yet.</div>
          )}
          {data && data.items.length > 0 && (
            <table className="data">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((project: Project) => (
                  <tr key={project.id}>
                    <td>
                      <Link to={`/projects/${project.id}`}>{project.name}</Link>
                    </td>
                    <td className="mono">
                      {project.created_at.slice(0, 19).replace('T', ' ')}
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
