/**
 * Retrieval evaluation (spec Part 5 §96-§99).
 *
 * The objective is NOT maximum retrieval — it is USEFUL retrieval (§98).
 * This module provides a deterministic benchmark harness: run the
 * retriever over a labelled dataset and compute Recall@K, Precision@K,
 * MRR and NDCG (§97), plus duplicate rate and token statistics. Agent
 * utility metrics (§98) are derived from persisted query/result rows.
 */
import type { RetrievedChunk } from '@aegis/contracts';

export interface BenchmarkQuery {
  query: string;
  categories?: string[];
  technologies?: string[];
  /** Expected document ids (ground truth) for this query. */
  expectedDocumentIds: string[];
}

export interface RetrievalMetrics {
  queries: number;
  recallAtK: number;
  precisionAtK: number;
  mrr: number;
  ndcg: number;
  duplicateRate: number;
  tokensRetrieved: number;
}

function dcg(relevances: number[]): number {
  return relevances.reduce((sum, relevance, index) => sum + (relevance > 0 ? 1 / Math.log2(index + 2) : 0), 0);
}

/**
 * Compute retrieval metrics over ranked result lists (§97).
 * `k` applies to Recall@K / Precision@K; MRR and NDCG use the full list.
 */
export function computeMetrics(
  datasets: Array<{ expectedDocumentIds: string[]; results: RetrievedChunk[] }>,
  k = 5,
): RetrievalMetrics {
  if (datasets.length === 0) {
    return { queries: 0, recallAtK: 0, precisionAtK: 0, mrr: 0, ndcg: 0, duplicateRate: 0, tokensRetrieved: 0 };
  }
  let recallSum = 0;
  let precisionSum = 0;
  let mrrSum = 0;
  let ndcgSum = 0;
  let duplicateCount = 0;
  let tokenSum = 0;

  for (const { expectedDocumentIds, results } of datasets) {
    const expected = new Set(expectedDocumentIds);
    if (expected.size === 0) continue;
    const top = results.slice(0, k);
    const hitsTop = top.filter((result) => expected.has(result.document_id)).length;
    recallSum += hitsTop / expected.size;
    precisionSum += top.length > 0 ? hitsTop / top.length : 0;

    // MRR: reciprocal rank of the first relevant result.
    const firstIndex = results.findIndex((result) => expected.has(result.document_id));
    mrrSum += firstIndex >= 0 ? 1 / (firstIndex + 1) : 0;

    // NDCG over the full ranked list with binary relevance.
    const relevances = results.map((result) => (expected.has(result.document_id) ? 1 : 0));
    const ideal = [...relevances].sort((a, b) => b - a);
    ndcgSum += dcg(ideal) > 0 ? dcg(relevances) / dcg(ideal) : 0;

    // Duplicate rate: repeated document ids inside the result list (§97).
    const seen = new Set<string>();
    for (const result of results) {
      if (seen.has(result.document_id)) duplicateCount += 1;
      seen.add(result.document_id);
      tokenSum += result.token_estimate;
    }
  }

  const queries = datasets.length;
  return {
    queries,
    recallAtK: recallSum / queries,
    precisionAtK: precisionSum / queries,
    mrr: mrrSum / queries,
    ndcg: ndcgSum / queries,
    duplicateRate: tokenSum > 0 || resultsLength(datasets) > 0 ? duplicateCount / Math.max(1, resultsLength(datasets)) : 0,
    tokensRetrieved: tokenSum,
  };
}

function resultsLength(datasets: Array<{ results: RetrievedChunk[] }>): number {
  return datasets.reduce((sum, dataset) => sum + dataset.results.length, 0);
}

/**
 * Default benchmark dataset shape (§96): authorization, JWT, XSS, CSRF,
 * SSRF, API security, GraphQL, WebSocket, business logic, race conditions,
 * CTF riddles and framework behaviour. Concrete document ids are supplied
 * by the test fixture corpus at runtime.
 */
export const BENCHMARK_QUERY_TEMPLATES: Array<{ query: string; categories: string[] }> = [
  { query: 'object level authorization failure for REST API resource identifiers', categories: ['AUTHORIZATION', 'API'] },
  { query: 'JWT audience validation and algorithm confusion', categories: ['AUTHENTICATION', 'SESSION'] },
  { query: 'cross-site scripting in template rendering', categories: ['XSS', 'CLIENT_SIDE'] },
  { query: 'cross-site request forgery protection with SameSite cookies', categories: ['CSRF', 'SESSION'] },
  { query: 'server-side request forgery via URL parameters', categories: ['SSRF'] },
  { query: 'GraphQL introspection and authorization depth attacks', categories: ['GRAPHQL', 'API'] },
  { query: 'WebSocket authentication and origin validation', categories: ['WEBSOCKET', 'AUTHENTICATION'] },
  { query: 'business logic workflow abuse in multi-step order processing', categories: ['BUSINESS_LOGIC'] },
  { query: 'race condition in concurrent balance updates', categories: ['RACE_CONDITION'] },
  { query: 'legacy API version differences and deprecated endpoints', categories: ['API', 'CONFIGURATION'] },
  { query: 'session fixation after authentication', categories: ['SESSION'] },
  { query: 'IDOR horizontal privilege escalation object reference', categories: ['AUTHORIZATION'] },
];

/** Agent utility metrics (§98) from persisted query rows. */
export function agentUtilityMetrics(rows: Array<{ cache_hit: boolean; result_count: number; tokens_estimate: number }>): {
  queries: number;
  cacheHitRate: number;
  avgResultsPerQuery: number;
  avgTokensPerQuery: number;
  zeroResultQueries: number;
} {
  if (rows.length === 0) {
    return { queries: 0, cacheHitRate: 0, avgResultsPerQuery: 0, avgTokensPerQuery: 0, zeroResultQueries: 0 };
  }
  return {
    queries: rows.length,
    cacheHitRate: rows.filter((row) => row.cache_hit).length / rows.length,
    avgResultsPerQuery: rows.reduce((sum, row) => sum + row.result_count, 0) / rows.length,
    avgTokensPerQuery: rows.reduce((sum, row) => sum + row.tokens_estimate, 0) / rows.length,
    zeroResultQueries: rows.filter((row) => row.result_count === 0).length,
  };
}
