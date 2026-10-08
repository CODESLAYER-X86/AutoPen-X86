import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { ScopeRequestSchema, ScopeResponseSchema, ScopeSchema, type Scope } from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, SuccessBanner } from '../../components/Feedback.js';

const SCHEMES = ['http', 'https', 'ws', 'wss'] as const;

function linesToList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line.length > 0);
}

function listToLines(list: string[] | undefined): string {
  return (list ?? []).join('\n');
}

export function ScopeTab({
  engagementId,
  onChanged,
}: {
  engagementId: string;
  onChanged: () => void;
}): ReactNode {
  const { data, error, loading, reload } = useResource(
    () => apiRequest('GET', `/api/engagements/${engagementId}/scope`, ScopeResponseSchema),
    [engagementId],
  );
  const scope: Scope | null = data?.scope ?? null;

  const [allowedHosts, setAllowedHosts] = useState('');
  const [allowedDomains, setAllowedDomains] = useState('');
  const [allowedPorts, setAllowedPorts] = useState('');
  const [schemes, setSchemes] = useState<string[]>(['http', 'https']);
  const [excludedHosts, setExcludedHosts] = useState('');
  const [excludedPaths, setExcludedPaths] = useState('');
  const [destructive, setDestructive] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [initialised, setInitialised] = useState(false);

  useEffect(() => {
    if (scope && !initialised) {
      setAllowedHosts(listToLines(scope.allowed_hosts));
      setAllowedDomains(listToLines(scope.allowed_domains));
      setAllowedPorts((scope.allowed_ports ?? []).join(', '));
      setSchemes(scope.allowed_schemes ?? ['http', 'https']);
      setExcludedHosts(listToLines(scope.excluded_hosts));
      setExcludedPaths(listToLines(scope.excluded_paths));
      setDestructive(scope.destructive_actions_allowed);
      setInitialised(true);
    }
  }, [scope, initialised]);

  const onSave = async (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    setSuccess(null);
    setBusy(true);
    try {
      const ports = allowedPorts
        .split(/[\s,]+/)
        .map((p) => Number(p))
        .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
      const body = ScopeRequestSchema.parse({
        allowed_hosts: linesToList(allowedHosts),
        allowed_domains: linesToList(allowedDomains),
        allowed_ports: ports,
        allowed_schemes: schemes,
        excluded_hosts: linesToList(excludedHosts),
        excluded_paths: excludedPaths
          .split('\n')
          .map((p) => p.trim())
          .filter((p) => p.length > 0),
        destructive_actions_allowed: destructive,
      });
      await apiRequest('POST', `/api/engagements/${engagementId}/scope`, ScopeSchema, body);
      setSuccess('Scope saved. In-scope targets are validated against these rules.');
      setInitialised(false);
      reload();
      onChanged();
    } catch (err) {
      if (err instanceof ApiError) {
        setFormError(`${err.message}\n${JSON.stringify(err.details, null, 2)}`);
      } else if (err instanceof Error) {
        // Client-side zod validation failure.
        setFormError(`Invalid scope: ${err.message}`);
      } else {
        setFormError('Unexpected error while saving the scope');
      }
    } finally {
      setBusy(false);
    }
  };

  const toggleScheme = (scheme: string) => {
    setSchemes((current) =>
      current.includes(scheme) ? current.filter((s) => s !== scheme) : [...current, scheme],
    );
  };

  return (
    <div className="grid grid-2">
      <div className="card">
        <div className="card-title">Configure scope (allowlist)</div>
        <form className="form" onSubmit={onSave}>
          <label className="field">
            Allowed hosts (exact, one per line)
            <textarea
              value={allowedHosts}
              onChange={(e) => setAllowedHosts(e.target.value)}
              placeholder={'localhost\n10.10.0.5'}
            />
          </label>
          <label className="field">
            Allowed domains (suffix match, one per line)
            <textarea
              value={allowedDomains}
              onChange={(e) => setAllowedDomains(e.target.value)}
              placeholder={'example.com\nlab.internal'}
            />
          </label>
          <label className="field">
            Allowed ports (comma separated; empty = scheme defaults only)
            <input
              value={allowedPorts}
              onChange={(e) => setAllowedPorts(e.target.value)}
              placeholder="80, 443, 8080"
            />
          </label>
          <div className="field">
            Allowed schemes (at least one)
            <div style={{ display: 'flex', gap: 16, marginTop: 4 }}>
              {SCHEMES.map((scheme) => (
                <label key={scheme} className="check-row">
                  <input
                    type="checkbox"
                    checked={schemes.includes(scheme)}
                    onChange={() => toggleScheme(scheme)}
                  />
                  {scheme}
                </label>
              ))}
            </div>
          </div>
          <label className="field">
            Excluded hosts
            <textarea
              value={excludedHosts}
              onChange={(e) => setExcludedHosts(e.target.value)}
              placeholder={'admin.example.com'}
            />
          </label>
          <label className="field">
            Excluded path prefixes
            <textarea
              value={excludedPaths}
              onChange={(e) => setExcludedPaths(e.target.value)}
              placeholder={'/admin\n/.git'}
            />
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={destructive}
              onChange={(e) => setDestructive(e.target.checked)}
            />
            Allow destructive actions (DELETE, drops, destructive tools)
          </label>
          <ErrorBanner message={formError} />
          <SuccessBanner message={success} />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save scope'}
          </button>
        </form>
      </div>

      <div className="card">
        <div className="card-title">Current scope</div>
        {loading && <Loading label="loading scope" />}
        {error && <ErrorBanner message={error} />}
        {!loading && !error && !scope && (
          <div className="empty-state">
            No scope configured. Targets cannot be added until a scope exists.
          </div>
        )}
        {scope && (
          <dl className="kv">
            <dt>Allowed hosts</dt>
            <dd>{scope.allowed_hosts.join(', ') || '—'}</dd>
            <dt>Allowed domains</dt>
            <dd>{scope.allowed_domains.join(', ') || '—'}</dd>
            <dt>Allowed ports</dt>
            <dd>{scope.allowed_ports.join(', ') || 'scheme defaults'}</dd>
            <dt>Allowed schemes</dt>
            <dd>{scope.allowed_schemes.join(', ')}</dd>
            <dt>Excluded hosts</dt>
            <dd>{scope.excluded_hosts.join(', ') || '—'}</dd>
            <dt>Excluded paths</dt>
            <dd>{scope.excluded_paths.join(', ') || '—'}</dd>
            <dt>Destructive actions</dt>
            <dd>{scope.destructive_actions_allowed ? 'ALLOWED' : 'forbidden'}</dd>
            <dt>Updated</dt>
            <dd>{scope.updated_at}</dd>
          </dl>
        )}
      </div>
    </div>
  );
}
