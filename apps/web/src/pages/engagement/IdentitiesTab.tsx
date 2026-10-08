import { useState, type FormEvent, type ReactNode } from 'react';
import {
  CreateIdentityRequestSchema,
  IdentitySchema,
  pageSchema,
  type Identity,
} from '@aegis/contracts';
import { IDENTITY_TYPES, type IdentityType } from '@aegis/shared';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, SuccessBanner, EmptyState } from '../../components/Feedback.js';
import { TypeBadge } from '../../components/StatusBadge.js';

const IdentitiesPageSchema = pageSchema(IdentitySchema);

export function IdentitiesTab({ engagementId }: { engagementId: string }): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/identities`, IdentitiesPageSchema),
    [engagementId],
  );
  const [name, setName] = useState('');
  const [role, setRole] = useState('');
  const [type, setType] = useState<IdentityType>('USER');
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onCreate = async (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    setSuccess(null);
    setBusy(true);
    try {
      const body = CreateIdentityRequestSchema.parse({ name, role, type });
      const identity = await apiRequest(
        'POST',
        `/api/engagements/${engagementId}/identities`,
        IdentitySchema,
        body,
      );
      setSuccess(`Identity '${identity.name}' created`);
      setName('');
      setRole('');
      reload();
    } catch (err) {
      setFormError(
        err instanceof ApiError
          ? `${err.message}${err.details ? `\n${JSON.stringify(err.details)}` : ''}`
          : 'Unexpected error while creating the identity',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid grid-2">
      <div className="card">
        <div className="card-title">Create identity</div>
        <form className="form" onSubmit={onCreate}>
          <div className="form-row">
            <label className="field">
              Name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                maxLength={200}
                placeholder="Admin"
              />
            </label>
            <label className="field">
              Role
              <input
                value={role}
                onChange={(e) => setRole(e.target.value)}
                maxLength={100}
                placeholder="administrator"
              />
            </label>
          </div>
          <label className="field">
            Type
            <select value={type} onChange={(e) => setType(e.target.value as IdentityType)}>
              {IDENTITY_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <ErrorBanner message={formError} />
          <SuccessBanner message={success} />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Creating…' : 'Create identity'}
          </button>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, margin: 0 }}>
            Credentials for identities are attached as sessions (cookies/JWTs) in later parts and
            are stored only as encrypted secret references — never in the database or model
            context.
          </p>
        </form>
      </div>

      <div className="card">
        <div className="card-title">Identities {data ? `(${data.total})` : ''}</div>
        {loading && <Loading label="loading identities" />}
        {error && <ErrorBanner message={error} />}
        {data && data.items.length === 0 && (
          <EmptyState>
            No identities yet (e.g. Anonymous, User A, Admin). Identities are optional until
            authenticated testing is enabled.
          </EmptyState>
        )}
        {data && data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Role</th>
                <th>Type</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((identity: Identity) => (
                <tr key={identity.id}>
                  <td>{identity.name}</td>
                  <td>{identity.role || '—'}</td>
                  <td>
                    <TypeBadge type={identity.type} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
