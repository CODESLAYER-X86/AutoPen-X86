import type { ReactNode } from 'react';
import { z } from 'zod';
import { MetaResponseSchema, ToolDescriptorSchema } from '@aegis/contracts';
import { apiRequest } from '../lib/api.js';
import { useResource } from '../hooks/useResource.js';
import { ErrorBanner, Loading } from '../components/Feedback.js';

const ToolsListSchema = z.object({
  items: z.array(ToolDescriptorSchema),
  total: z.number().int(),
  implemented: z.number().int(),
});

export function SettingsPage(): ReactNode {
  const meta = useResource(() => apiRequest('GET', '/api/meta', MetaResponseSchema), []);
  const tools = useResource(() => apiRequest('GET', '/api/tools', ToolsListSchema), []);

  return (
    <div>
      <h1 className="page-title">Settings</h1>
      <p className="page-subtitle">
        Runtime configuration is supplied by the server environment (.env); model roles and
        feature flags change via configuration, never code.
      </p>

      {meta.error && <ErrorBanner message={meta.error} />}
      {meta.loading && <Loading label="loading configuration" />}
      {meta.data && (
        <div className="grid grid-2">
          <div className="card">
            <div className="card-title">Model runtime</div>
            <dl className="kv">
              <dt>Environment</dt>
              <dd>{meta.data.environment}</dd>
              <dt>Strategic provider</dt>
              <dd>
                {meta.data.models.strategic.provider} · {meta.data.models.strategic.model_id}
              </dd>
              <dt>Tactical provider</dt>
              <dd>
                {meta.data.models.tactical.provider} · {meta.data.models.tactical.model_id}
              </dd>
              <dt>Google API key configured</dt>
              <dd>{meta.data.models.google_api_key_configured ? 'yes' : 'no (mock provider used)'}</dd>
            </dl>
            <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 12 }}>
              Set STRATEGIC_MODEL_PROVIDER / TACTICAL_MODEL_PROVIDER and the corresponding
              *_MODEL_ID environment variables to change models without code changes.
            </p>
          </div>

          <div className="card">
            <div className="card-title">Feature flags</div>
            <dl className="kv">
              <dt>FEATURE_TOOLS_HTTP</dt>
              <dd>{String(meta.data.features.tools_http)}</dd>
              <dt>FEATURE_TOOLS_BROWSER</dt>
              <dd>{String(meta.data.features.tools_browser)}</dd>
              <dt>FEATURE_KNOWLEDGE_SEARCH</dt>
              <dd>{String(meta.data.features.knowledge_search)}</dd>
              <dt>FEATURE_REPORTING</dt>
              <dd>{String(meta.data.features.reporting)}</dd>
            </dl>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-title">
          Tool registry {tools.data ? `(${tools.data.implemented}/${tools.data.total} implemented)` : ''}
        </div>
        {tools.error && <ErrorBanner message={tools.error} />}
        {tools.loading && <Loading label="loading tools" />}
        {tools.data && (
          <table className="data">
            <thead>
              <tr>
                <th>Name</th>
                <th>Risk</th>
                <th>Capabilities</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {tools.data.items.map((tool) => (
                <tr key={tool.name}>
                  <td className="mono" title={tool.description}>
                    {tool.name}
                  </td>
                  <td>
                    <span
                      className={`badge ${
                        tool.risk_level === 'HIGH' || tool.risk_level === 'CRITICAL'
                          ? 'badge-red'
                          : tool.risk_level === 'MEDIUM'
                            ? 'badge-yellow'
                            : 'badge-gray'
                      }`}
                    >
                      {tool.risk_level}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {tool.capabilities.join(', ')}
                  </td>
                  <td>
                    {tool.implemented ? (
                      <span className="badge badge-green">implemented</span>
                    ) : (
                      <span className="badge badge-yellow">
                        not implemented{tool.planned_part ? ` · ${tool.planned_part}` : ''}
                      </span>
                    )}
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
