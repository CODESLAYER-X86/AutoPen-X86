/**
 * Provider abstraction seams (spec Part 5 §114).
 *
 * KeywordIndex / VectorIndex / WebSearchProvider / Reranker surfaces are
 * interfaces so infrastructure can change without rewriting the engine
 * (no lock-in; PostgreSQL FTS + in-process cosine over stored vectors are
 * the initial implementations).
 */
import type { Pool } from 'pg';

export interface KeywordHit {
  chunkId: string;
  score: number;
}

/** Keyword retrieval over the chunk corpus (§13). */
export interface KeywordIndex {
  search(query: string, limit: number, options?: { sourceIds?: string[] }): Promise<KeywordHit[]>;
}

/**
 * PostgreSQL full-text keyword index: websearch_to_tsquery over
 * heading + content with ts_rank scoring (§13). GIN index provided by
 * migration 054.
 */
export class PostgresFtsKeywordIndex implements KeywordIndex {
  constructor(private readonly pool: Pool) {}

  async search(query: string, limit: number, options?: { sourceIds?: string[] }): Promise<KeywordHit[]> {
    const trimmed = query.trim().slice(0, 500);
    if (!trimmed) return [];
    const params: unknown[] = [trimmed, Math.min(Math.max(limit, 1), 100)];
    let sourceFilter = '';
    if (options?.sourceIds && options.sourceIds.length > 0) {
      params.push(options.sourceIds.slice(0, 50));
      sourceFilter = 'AND d.source_id = ANY($3::text[])';
    }
    const result = await this.pool.query<{ chunk_id: string; score: number }>(
      `SELECT c.id AS chunk_id,
              ts_rank(to_tsvector('english', coalesce(c.heading, '') || ' ' || c.content), query) AS score
       FROM knowledge_chunks c
       JOIN knowledge_documents d ON d.id = c.document_id AND d.is_latest
       CROSS JOIN websearch_to_tsquery('english', $1) AS query
       WHERE to_tsvector('english', coalesce(c.heading, '') || ' ' || c.content) @@ query
         ${sourceFilter}
       ORDER BY score DESC, c.id
       LIMIT $2`,
      params,
    );
    return result.rows.map((row) => ({ chunkId: row.chunk_id, score: Number(row.score) }));
  }
}

export interface VectorCandidate {
  chunkId: string;
  embedding: number[];
}

export interface VectorHit {
  chunkId: string;
  score: number;
}

/**
 * Vector similarity surface (§14). The initial implementation loads a
 * bounded set of stored vectors for the active embedding model and ranks
 * them in-process — deliberately simple, honest about scale; a dedicated
 * vector store can replace it behind the same interface (§114).
 */
export interface VectorIndex {
  search(queryEmbedding: number[], limit: number): Promise<VectorHit[]>;
}

export function rankVectors(
  queryEmbedding: number[],
  candidates: VectorCandidate[],
  limit: number,
  similarity: (a: number[], b: number[]) => number,
): VectorHit[] {
  const hits = candidates
    .map((candidate) => ({ chunkId: candidate.chunkId, score: similarity(queryEmbedding, candidate.embedding) }))
    .filter((hit) => hit.score > 0)
    .sort((a, b) => b.score - a.score);
  return hits.slice(0, Math.min(Math.max(limit, 1), 200));
}

// ---------------------------------------------------------------------------
// Web search (§33, §32).
// ---------------------------------------------------------------------------

export interface WebSearchResult {
  title: string;
  url: string;
  snippet: string;
  domain: string;
}

export interface WebSearchProvider {
  readonly id: string;
  readonly model: string;
  search(
    query: string,
    options: { maxResults: number; domainAllowlist?: string[]; domainDenylist?: string[] },
  ): Promise<{ results: WebSearchResult[]; note?: string }>;
}

/**
 * Honest null provider: live web search requires an external provider
 * (API key). Without configuration the platform reports this explicitly
 * instead of pretending to search (§104: unrestricted research is never
 * silently enabled). Tests inject a deterministic fake provider.
 */
export class NullWebSearchProvider implements WebSearchProvider {
  readonly id = 'null';
  readonly model = 'none';

  async search(
    query: string,
    options: { maxResults: number; domainAllowlist?: string[]; domainDenylist?: string[] },
  ): Promise<{ results: WebSearchResult[]; note?: string }> {
    void query;
    void options;
    return {
      results: [],
      note: 'No web search provider is configured (set a search provider in configuration); local knowledge only',
    };
  }
}
