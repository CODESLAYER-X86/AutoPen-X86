/**
 * Knowledge tab — Part 5 web surface (spec Part 5 §112).
 *
 * Lets operators inspect the knowledge subsystem: source registry, hybrid
 * search over the local index with compact packets, similar-case retrieval
 * and the retrieval audit trail (recent queries).
 */
import type { ReactNode } from 'react';
import { useCallback, useState } from 'react';
import { z } from 'zod';
import { pageSchema } from '@aegis/contracts';
import { apiRequest, ApiError } from '../../lib/api.js';
import { useResource } from '../../hooks/useResource.js';
import { ErrorBanner, Loading, EmptyState } from '../../components/Feedback.js';

const SourceSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  base_url: z.string(),
  trust_level: z.string(),
  enabled: z.boolean(),
  update_strategy: z.string(),
  last_synced: z.string().nullable(),
});
const SourcesPageSchema = pageSchema(SourceSchema);

const PacketResultSchema = z.object({
  source_name: z.string(),
  title: z.string(),
  section: z.string().nullable(),
  trust_level: z.string(),
  relevance: z.number(),
  corroborated: z.boolean().default(false),
  content: z.string(),
  url: z.string(),
});
const PacketSchema = z.object({
  query: z.string(),
  cache_hit: z.boolean(),
  results: z.array(PacketResultSchema),
  total_available: z.number(),
  packet_tokens: z.number(),
  truncated: z.boolean().default(false),
  notes: z.array(z.string()).default([]),
});
const SimilarCaseSchema = z.object({
  title: z.string(),
  event: z.string().nullable(),
  year: z.number().nullable(),
  category: z.string().nullable(),
  technique: z.string().nullable(),
  relevance: z.number(),
  description_excerpt: z.string(),
});
const SimilarSchema = z.object({
  cases: z.array(SimilarCaseSchema),
  notes: z.array(z.string()).default([]),
});
const QueryRowSchema = z.object({
  id: z.string(),
  query: z.string(),
  requested_by: z.string(),
  mode: z.string(),
  cache_hit: z.boolean(),
  result_count: z.number(),
  tokens_estimate: z.number(),
  created_at: z.string(),
});
const QueriesPageSchema = pageSchema(QueryRowSchema);

function trustClass(level: string): string {
  switch (level) {
    case 'OFFICIAL':
      return 'badge ok';
    case 'TRUSTED_TRAINING':
      return 'badge info';
    case 'RESEARCH':
      return 'badge info';
    case 'CTF':
      return 'badge warn';
    default:
      return 'badge';
  }
}

export function KnowledgeTab({ engagementId }: { engagementId: string }): ReactNode {
  const sources = useResource(
    () => apiRequest('GET', '/api/knowledge/sources', SourcesPageSchema),
    [engagementId],
  );
  const queries = useResource(
    () => apiRequest('GET', '/api/knowledge/queries?limit=25', QueriesPageSchema),
    [engagementId],
  );

  const [query, setQuery] = useState('');
  const [categories, setCategories] = useState('');
  const [packet, setPacket] = useState<z.output<typeof PacketSchema> | null>(null);
  const [similar, setSimilar] = useState<z.output<typeof SimilarSchema> | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const runSearch = useCallback(async () => {
    const trimmed = query.trim();
    if (!trimmed) return;
    setBusy(true);
    setSearchError(null);
    setPacket(null);
    setSimilar(null);
    try {
      const [packetResult, similarResult] = await Promise.all([
        apiRequest('POST', '/api/knowledge/search', PacketSchema, {
          query: trimmed,
          engagement_id: engagementId,
          categories: categories
            .split(',')
            .map((c) => c.trim().toUpperCase())
            .filter(Boolean)
            .slice(0, 8),
          max_results: 8,
          max_tokens: 2500,
        }),
        apiRequest('POST', '/api/knowledge/similar', SimilarSchema, {
          engagement_id: engagementId,
          observation: trimmed,
          max_results: 4,
        }).catch(() => null),
      ]);
      setPacket(packetResult);
      if (similarResult) setSimilar(similarResult);
      queries.reload();
    } catch (err) {
      setSearchError(err instanceof ApiError ? err.message : 'Search failed unexpectedly');
    } finally {
      setBusy(false);
    }
  }, [query, categories, engagementId, queries]);

  return (
    <section className="stack">
      <div className="card">
        <h3>Knowledge Search</h3>
        <p className="dim">
          Hybrid retrieval (keyword + semantic) over the local knowledge index. Retrieved content is
          advisory reference material — never target evidence.
        </p>
        <div className="row">
          <input
            placeholder="e.g. object level authorization for REST API identifiers"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void runSearch();
            }}
            style={{ flex: 1 }}
          />
          <input
            placeholder="categories (AUTHORIZATION, SESSION…)"
            value={categories}
            onChange={(event) => setCategories(event.target.value)}
            style={{ width: 260 }}
          />
          <button type="button" disabled={busy || !query.trim()} onClick={() => void runSearch()}>
            {busy ? 'searching…' : 'Search'}
          </button>
        </div>
        <ErrorBanner message={searchError} />
        {packet && (
          <div className="stack">
            <p className="dim">
              {packet.results.length} result{packet.results.length === 1 ? '' : 's'}
              {packet.cache_hit ? ' (cache hit)' : ''} · ~{packet.packet_tokens} tokens
              {packet.truncated ? ' · truncated to budget' : ''} of {packet.total_available} available
            </p>
            {packet.notes.map((note) => (
              <p key={note} className="dim">
                {note}
              </p>
            ))}
            {packet.results.map((result, index) => (
              <div key={index} className="card inset">
                <div className="row spread">
                  <strong>{result.title}</strong>
                  <span className={trustClass(result.trust_level)}>{result.trust_level}</span>
                </div>
                <p className="dim">
                  {result.source_name}
                  {result.section ? ` · ${result.section}` : ''} · relevance{' '}
                  {Math.round(result.relevance * 100)}%
                  {result.corroborated ? ' · corroborated' : ''}
                </p>
                <pre className="excerpt">{result.content.slice(0, 800)}</pre>
              </div>
            ))}
            {packet.results.length === 0 && <EmptyState>No matching local knowledge.</EmptyState>}
          </div>
        )}
        {similar && similar.cases.length > 0 && (
          <div className="stack">
            <h4>Similar Cases (case memory)</h4>
            {similar.cases.map((item, index) => (
              <div key={index} className="card inset">
                <div className="row spread">
                  <strong>{item.title}</strong>
                  <span className="badge">{item.category ?? 'case'}</span>
                </div>
                <p className="dim">
                  {item.event ?? 'unknown event'}
                  {item.year ? ` ${item.year}` : ''} · relevance {Math.round(item.relevance * 100)}%
                  {item.technique ? ` · ${item.technique}` : ''}
                </p>
                <pre className="excerpt">{item.description_excerpt.slice(0, 400)}</pre>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <h3>Knowledge Sources</h3>
        <ErrorBanner message={sources.error} />
        {sources.loading && <Loading label="sources" />}
        {sources.data && sources.data.items.length === 0 && (
          <EmptyState>
            No sources yet — POST /api/knowledge/sync seeds the curated catalog (OWASP, PortSwigger,
            MDN, RFCs, CTF write-ups).
          </EmptyState>
        )}
        {sources.data && sources.data.items.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Trust</th>
                <th>Strategy</th>
                <th>Synced</th>
              </tr>
            </thead>
            <tbody>
              {sources.data.items.map((source) => (
                <tr key={source.id}>
                  <td>{source.name}</td>
                  <td>{source.type}</td>
                  <td>
                    <span className={trustClass(source.trust_level)}>{source.trust_level}</span>
                  </td>
                  <td>{source.update_strategy}</td>
                  <td>{source.last_synced ? new Date(source.last_synced).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3>Recent Retrieval Queries (audit trail)</h3>
        <ErrorBanner message={queries.error} />
        {queries.loading && <Loading label="queries" />}
        {queries.data && queries.data.items.length === 0 && <EmptyState>No queries yet.</EmptyState>}
        {queries.data && queries.data.items.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Query</th>
                <th>By</th>
                <th>Mode</th>
                <th>Results</th>
                <th>Tokens</th>
                <th>Cache</th>
                <th>At</th>
              </tr>
            </thead>
            <tbody>
              {queries.data.items.map((row) => (
                <tr key={row.id}>
                  <td title={row.query}>{row.query.slice(0, 80)}</td>
                  <td>{row.requested_by}</td>
                  <td>{row.mode}</td>
                  <td>{row.result_count}</td>
                  <td>{row.tokens_estimate}</td>
                  <td>{row.cache_hit ? 'hit' : 'miss'}</td>
                  <td>{new Date(row.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
