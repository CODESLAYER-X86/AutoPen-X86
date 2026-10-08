import { useState, type FormEvent, type ReactNode } from 'react';
import {
  CreateTargetRequestSchema,
  TargetSchema,
  pageSchema,
  type Target,
} from '@aegis/contracts';
import { TARGET_TYPES, type TargetType } from '@aegis/shared';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, SuccessBanner, EmptyState } from '../../components/Feedback.js';
import { TypeBadge } from '../../components/StatusBadge.js';

const TargetsPageSchema = pageSchema(TargetSchema);

export function TargetsTab({
  engagementId,
  onChanged,
}: {
  engagementId: string;
  onChanged: () => void;
}): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/targets`, TargetsPageSchema),
    [engagementId],
  );
  const [type, setType] = useState<TargetType>('URL');
  const [value, setValue] = useState('');
  const [label, setLabel] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onAdd = async (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    setSuccess(null);
    setBusy(true);
    try {
      const body = CreateTargetRequestSchema.parse({
        type,
        value,
        label: label || undefined,
      });
      const target = await apiRequest(
        'POST',
        `/api/engagements/${engagementId}/targets`,
        TargetSchema,
        body,
      );
      setSuccess(`Target accepted: ${target.value}`);
      setValue('');
      setLabel('');
      reload();
      onChanged();
    } catch (err) {
      if (err instanceof ApiError) {
        const details = err.details ? `\n${JSON.stringify(err.details, null, 2)}` : '';
        setFormError(`${err.message}${details}`);
      } else {
        setFormError('Unexpected error while adding the target');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid grid-2">
      <div className="card">
        <div className="card-title">Add target (scope-checked)</div>
        <form className="form" onSubmit={onAdd}>
          <label className="field">
            Type
            <select value={type} onChange={(e) => setType(e.target.value as TargetType)}>
              {TARGET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Value
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
              placeholder={type === 'URL' ? 'http://localhost:8080/' : 'example.com'}
            />
          </label>
          <label className="field">
            Label (optional)
            <input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={200} />
          </label>
          <ErrorBanner message={formError} />
          <SuccessBanner message={success} />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Validating…' : 'Add target'}
          </button>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, margin: 0 }}>
            The server validates every target against the engagement scope BEFORE storing it.
            Out-of-scope targets are rejected with a scope violation.
          </p>
        </form>
      </div>

      <div className="card">
        <div className="card-title">Targets {data ? `(${data.total})` : ''}</div>
        {loading && <Loading label="loading targets" />}
        {error && <ErrorBanner message={error} />}
        {data && data.items.length === 0 && (
          <EmptyState>No targets yet — configure the scope first, then add a target.</EmptyState>
        )}
        {data && data.items.length > 0 && (
          <table className="data">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((target: Target) => (
                <tr key={target.id}>
                  <td>
                    <TypeBadge type={target.type} />
                  </td>
                  <td className="mono">{target.value}</td>
                  <td>{target.label ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
