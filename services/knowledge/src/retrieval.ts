/**
 * Hybrid retrieval pipeline (spec Part 5 §15-§25, §68-§69, §73, §109, §111).
 *
 * query → normalization → keyword retrieval → semantic retrieval → merge →
 * deduplicate → rerank (trust/freshness/context/specificity) → bounded
 * candidate set for the packet builder.
 *
 * Scoring keeps the dimensions SEPARATE (§68): relevance, trust and
 * freshness are never collapsed into one number at the source; the final
 * score is a configurable weighted combination (§69) whose components are
 * each persisted (knowledge_results rows).
 */
import type { KnowledgeTrustLevel, SecurityTaxonomyCategory } from '@aegis/shared';
import { cosineSimilarity, type EmbeddingProvider } from './embeddings.js';
import { expandQuery } from './taxonomy.js';
import { estimateTokens } from './util.js';
import type { KeywordHit, KeywordIndex, VectorCandidate } from './providers.js';

// ---------------------------------------------------------------------------
// Scoring model (pure, unit-testable).
// ---------------------------------------------------------------------------

export interface RetrievalWeights {
  semantic: number;
  keyword: number;
  trust: number;
  freshness: number;
  context: number;
  specificity: number;
  duplicatePenalty: number;
}

export interface CandidateChunk {
  chunkId: string;
  documentId: string;
  sourceId: string;
  sourceName: string;
  url: string;
  title: string;
  heading: string | null;
  section: string | null;
  kind: string;
  content: string;
  trustLevel: KnowledgeTrustLevel;
  publishedAt: string | null;
  retrievedAt: string;
  contentHash: string;
  technologies: string[];
  categories: SecurityTaxonomyCategory[];
  keywordScore: number;
  semanticScore: number;
}

export interface ScoredCandidate {
  chunk: CandidateChunk;
  relevance: number;
  trustScore: number;
  freshnessScore: number;
  contextScore: number;
  specificityScore: number;
  finalScore: number;
  duplicatePenalized: boolean;
  corroborated: boolean;
  /** Internal: duplicate group adjustment applied before finalScore. */
  finalScoreAdjustment?: number;
}

/** Trust ranking factor (§23) — a factor, never a truth guarantee. */
export const TRUST_SCORES: Record<KnowledgeTrustLevel, number> = {
  OFFICIAL: 1.0,
  TRUSTED_TRAINING: 0.85,
  RESEARCH: 0.7,
  CTF: 0.55,
  COMMUNITY: 0.35,
  UNTRUSTED: 0.1,
};

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Freshness score (§24): current material outranks old material, BUT
 * historical CTF write-ups do not become useless merely for being old —
 * decay is capped by source trust intent. Freshness must never overwhelm
 * technical relevance (§130).
 */
export function freshnessScore(
  candidate: { publishedAt: string | null; retrievedAt: string; trustLevel: KnowledgeTrustLevel },
  now: number = Date.now(),
): number {
  const reference = candidate.publishedAt ? Date.parse(candidate.publishedAt) : Date.parse(candidate.retrievedAt);
  if (!Number.isFinite(reference)) return 0.5;
  const ageDays = Math.max(0, (now - reference) / DAY_MS);
  // Half-life ~2 years for most content; CTF knowledge decays slower (cap).
  const halfLifeDays = candidate.trustLevel === 'CTF' ? 3650 : 730;
  const score = Math.pow(0.5, ageDays / halfLifeDays);
  return Math.max(0.1, Math.min(1, score));
}

/**
 * Context relevance (§18): taxonomy + technology overlap between the query
 * context and the document metadata.
 */
export function contextScore(
  candidate: { technologies: string[]; categories: SecurityTaxonomyCategory[]; heading: string | null; content: string },
  context: { categories: SecurityTaxonomyCategory[]; technologies: string[] },
): number {
  let score = 0;
  if (context.categories.length > 0) {
    const overlap = candidate.categories.filter((c) => context.categories.includes(c)).length;
    score += Math.min(1, overlap / Math.max(1, Math.min(context.categories.length, 3))) * 0.6;
  }
  if (context.technologies.length > 0) {
    const loweredContent = `${candidate.heading ?? ''} ${candidate.content}`.toLowerCase();
    const techHits = context.technologies.filter(
      (tech) => loweredContent.includes(tech.toLowerCase()) || candidate.technologies.includes(tech),
    ).length;
    score += Math.min(1, techHits / Math.max(1, context.technologies.length)) * 0.4;
  }
  return Math.min(1, score);
}

/** Specificity: precise headings/short chunks rank above generic boilerplate. */
export function specificityScore(candidate: { heading: string | null; content: string }): number {
  const heading = candidate.heading ?? '';
  let score = 0.5;
  if (heading.length > 0 && heading.length <= 120) score += 0.2;
  const tokens = estimateTokens(candidate.content);
  if (tokens >= 200 && tokens <= 900) score += 0.2;
  if (/^(?:introduction|overview|table of contents|index|about|home|privacy|license|copyright)/i.test(heading)) {
    score -= 0.3;
  }
  return Math.max(0, Math.min(1, score));
}

/**
 * Rerank merged candidates (§22, §69). Relevance is the blend of keyword
 * and semantic scores (§15); trust, freshness, context and specificity are
 * additive ranking factors. Duplicates (same content hash under another
 * source) keep provenance but are penalized and marked (§67, §109).
 */
export function rerank(
  candidates: CandidateChunk[],
  weights: RetrievalWeights,
  context: { categories: SecurityTaxonomyCategory[]; technologies: string[] },
  now: number = Date.now(),
): ScoredCandidate[] {
  // Keyword score normalization: ts_rank is unbounded — normalize against
  // the best observed score so the blend is comparable (§15).
  const maxKeyword = Math.max(...candidates.map((c) => c.keywordScore), 1e-9);

  // Duplicate detection across sources by content hash (§67/§109).
  const byHash = new Map<string, ScoredCandidate[]>();
  const prelim: ScoredCandidate[] = candidates.map((chunk) => {
    const keyword = chunk.keywordScore / maxKeyword;
    const blended =
      weights.semantic + weights.keyword > 0
        ? (chunk.semanticScore * weights.semantic + keyword * weights.keyword) /
          (weights.semantic + weights.keyword)
        : (chunk.semanticScore + keyword) / 2;
    const trust = TRUST_SCORES[chunk.trustLevel] ?? 0.1;
    const scored: ScoredCandidate = {
      chunk,
      relevance: Math.max(0, Math.min(1, blended)),
      trustScore: trust,
      freshnessScore: freshnessScore(chunk, now),
      contextScore: contextScore(chunk, context),
      specificityScore: specificityScore(chunk),
      finalScore: 0,
      duplicatePenalized: false,
      corroborated: false,
    };
    const list = byHash.get(chunk.contentHash) ?? [];
    list.push(scored);
    byHash.set(chunk.contentHash, list);
    return scored;
  });

  for (const group of byHash.values()) {
    if (group.length > 1) {
      // Keep the highest-trust instance primary; others become penalized
      // duplicates whose provenance is retained (§109: primary + one
      // corroborating source + provenance is sufficient).
      group.sort((a, b) => b.trustScore - a.trustScore || b.relevance - a.relevance);
      const distinctSources = new Set(group.map((g) => g.chunk.sourceId)).size;
      group.forEach((entry, index) => {
        if (index > 0) {
          entry.duplicatePenalized = true;
          entry.finalScoreAdjustment = -weights.duplicatePenalty;
        }
        // Cross-source agreement on identical content = corroboration (§73).
        if (distinctSources > 1) {
          entry.corroborated = true;
        }
      });
    }
  }

  for (const entry of prelim) {
    entry.finalScore =
      entry.relevance +
      weights.trust * entry.trustScore +
      weights.freshness * entry.freshnessScore +
      weights.context * entry.contextScore +
      weights.specificity * entry.specificityScore +
      (entry.finalScoreAdjustment ?? 0);
  }

  prelim.sort((a, b) => b.finalScore - a.finalScore);
  return prelim;
}

// ---------------------------------------------------------------------------
// Source disagreement detection (§73, §111) — preserved, never averaged.
// ---------------------------------------------------------------------------

export interface KnowledgeDisagreement {
  topic: string;
  position_a: string;
  position_b: string;
}

/**
 * Detect preserved disagreement among top results: two high-relevance
 * results from reputable sources covering the same category but with
 * dissimilar content. Coarse lexical similarity is intentional — this is a
 * HINT for the leader to verify, not a semantic claim (§78).
 */
export function detectDisagreements(top: ScoredCandidate[], max = 4): KnowledgeDisagreement[] {
  const reputable = top.filter(
    (entry) =>
      (entry.chunk.trustLevel === 'OFFICIAL' || entry.chunk.trustLevel === 'TRUSTED_TRAINING') &&
      entry.relevance >= 0.3,
  );
  const disagreements: KnowledgeDisagreement[] = [];
  for (let i = 0; i < reputable.length && disagreements.length < max; i += 1) {
    for (let j = i + 1; j < reputable.length && disagreements.length < max; j += 1) {
      const a = reputable[i]!;
      const b = reputable[j]!;
      if (a.chunk.contentHash === b.chunk.contentHash) continue;
      const sharedHeadingWord = (a.chunk.heading ?? '').toLowerCase().split(/\s+/);
      const otherHeading = (b.chunk.heading ?? '').toLowerCase();
      const topical = sharedHeadingWord.some((w) => w.length > 4 && otherHeading.includes(w));
      if (!topical) continue;
      const similarity = jaccard(
        new Set(tokenize(a.chunk.content)),
        new Set(tokenize(b.chunk.content)),
      );
      // Same topic, very different content → possible disagreement.
      if (similarity < 0.12) {
        disagreements.push({
          topic: a.chunk.heading ?? a.chunk.title,
          position_a: `${a.chunk.sourceName}: ${(a.chunk.heading ?? '').slice(0, 120)}`,
          position_b: `${b.chunk.sourceName}: ${(b.chunk.heading ?? b.chunk.title).slice(0, 120)}`,
        });
      }
    }
  }
  return disagreements;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length > 3);
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) if (b.has(item)) intersection += 1;
  return intersection / (a.size + b.size - intersection);
}

// ---------------------------------------------------------------------------
// Hybrid retriever (wires the indexes + repositories).
// ---------------------------------------------------------------------------

export interface HybridRetrieverDeps {
  keywordIndex: KeywordIndex;
  embeddingProvider: EmbeddingProvider;
  loadCandidates: (chunkIds: string[]) => Promise<CandidateChunk[]>;
  loadVectors: (model: string) => Promise<VectorCandidate[]>;
}

export interface RetrieveOptions {
  query: string;
  limit: number;
  categories: SecurityTaxonomyCategory[];
  technologies: string[];
  weights: RetrievalWeights;
  sourceIds?: string[];
}

export interface RetrievalOutcome {
  scored: ScoredCandidate[];
  keywordHits: number;
  semanticHits: number;
  expandedTerms: string[];
}

/**
 * Hybrid retrieval (§20): keyword + semantic paths merged, deduplicated and
 * reranked. The semantic path is optional: when embeddings are disabled or
 * the vector store is empty the keyword path still works (§116).
 */
export class HybridRetriever {
  constructor(private readonly deps: HybridRetrieverDeps) {}

  async retrieve(options: RetrieveOptions): Promise<RetrievalOutcome> {
    const { query, limit, categories, technologies, weights } = options;
    const expandedTerms = expandQuery(query);
    const keywordQuery = [query, ...expandedTerms].join(' ');

    const keywordHits: KeywordHit[] = await this.deps.keywordIndex.search(
      keywordQuery,
      Math.min(limit * 6, 60),
      options.sourceIds ? { sourceIds: options.sourceIds } : undefined,
    );

    // Semantic path: embed the query once, rank against stored vectors.
    let semanticHits: Array<{ chunkId: string; score: number }> = [];
    const canEmbed = this.deps.embeddingProvider.dimension > 0;
    if (canEmbed) {
      const [queryEmbedding, vectors] = await Promise.all([
        this.deps.embeddingProvider.embed([query]),
        this.deps.loadVectors(this.deps.embeddingProvider.model),
      ]);
      const queryVector = queryEmbedding[0];
      if (queryVector) {
        semanticHits = vectors
          .map((candidate) => ({
            chunkId: candidate.chunkId,
            score: cosineSimilarity(queryVector, candidate.embedding),
          }))
          .filter((hit) => hit.score > 0.02)
          .sort((a, b) => b.score - a.score)
          .slice(0, limit * 6);
      }
    }

    // Merge + deduplicate by chunk id (§20).
    const keywordScoreById = new Map(keywordHits.map((hit) => [hit.chunkId, hit.score]));
    const semanticScoreById = new Map(semanticHits.map((hit) => [hit.chunkId, hit.score]));
    const mergedIds = [...new Set([...keywordScoreById.keys(), ...semanticScoreById.keys()])].slice(0, 200);

    const candidates = await this.deps.loadCandidates(mergedIds);
    const byId = new Map(candidates.map((c) => [c.chunkId, c]));
    const merged: CandidateChunk[] = [];
    for (const id of mergedIds) {
      const candidate = byId.get(id);
      if (!candidate) continue;
      merged.push({
        ...candidate,
        keywordScore: keywordScoreById.get(id) ?? 0,
        semanticScore: semanticScoreById.get(id) ?? 0,
      });
    }

    const scored = rerank(merged, weights, { categories, technologies });
    return { scored, keywordHits: keywordHits.length, semanticHits: semanticHits.length, expandedTerms };
  }
}
