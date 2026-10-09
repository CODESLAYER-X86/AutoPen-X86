/**
 * KnowledgeEngine — the top-level facade of the Security Knowledge & Web
 * Research System (spec Part 5 §1, §113, §120, §133).
 *
 * Implements the KnowledgeService interface (Part 1 contract) with the real
 * Part 5 subsystem:
 *
 *  search()      — hybrid retrieval → rerank → compact packet (§15-§25, §61)
 *  similarCases() — case memory + CTF pattern retrieval (§36-§42)
 *  fetch()       — bounded live fetch → ingestion pipeline (§26, §115)
 *  research()    — bounded, audited live research (§30-§33, §72)
 *  sync()        — curated source synchronization (§29)
 *
 * KNOWLEDGE != EVIDENCE and KNOWLEDGE != AUTHORITY (§135): nothing in this
 * engine can modify scope, permissions, credentials or agent policy.
 */
import type { Pool } from 'pg';
import type { Repositories, KnowledgeSourceRecord } from '@aegis/database';
import type {
  IngestionOutcome,
  KnowledgeContextProvider,
  KnowledgeFetchRequest,
  KnowledgePacket,
  KnowledgeSearchRequest,
  PlatformEvent,
  ResearchRequest,
  ResearchResult,
  SimilarCaseRequest,
  SimilarCaseResult,
} from '@aegis/contracts';
import { generateId, type SecurityTaxonomyCategory } from '@aegis/shared';
import type { AppConfig } from '@aegis/config';
import type { ObjectStore } from '@aegis/evidence';
import { GoogleEmbeddingProvider, HashingEmbeddingProvider, NoneEmbeddingProvider, type EmbeddingProvider } from './embeddings.js';
import { KnowledgeFetcher } from './fetcher.js';
import { NullWebSearchProvider, PostgresFtsKeywordIndex, type WebSearchProvider } from './providers.js';
import { HybridRetriever, detectDisagreements, type CandidateChunk } from './retrieval.js';
import { buildPacket } from './packets.js';
import { IngestionPipeline } from './ingestion.js';
import { matchTechniques } from './techniques.js';
import { ResearchEngine } from './research.js';
import { ingestCtfWriteup, similarCases } from './case-memory.js';
import { CURATED_SOURCE_CATALOG } from './sources.js';
import { buildCacheKey } from './util.js';
import { agentUtilityMetrics } from './eval.js';

export interface KnowledgeEngineDeps {
  pool: Pool;
  repos: Repositories;
  config: AppConfig;
  objectStore?: ObjectStore;
  eventBus: { publish(event: PlatformEvent): Promise<void> };
  logger?: { info: (event: string, fields?: Record<string, unknown>) => void; warn: (event: string, fields?: Record<string, unknown>) => void };
  /** Injectable web search provider (tests / future operators). */
  webSearchProvider?: WebSearchProvider;
  /** Injectable embedding provider (tests). */
  embeddingProvider?: EmbeddingProvider;
}

export interface KnowledgeStatus {
  sources: number;
  documents: number;
  chunks: number;
  embeddings: number;
  techniques: number;
  references: number;
  queries: number;
  researchTasks: number;
  embeddingModel: string;
  embeddingDimension: number;
  cache: { activeEntries: number };
  agentUtility: ReturnType<typeof agentUtilityMetrics>;
}

export class KnowledgeEngine implements KnowledgeContextProvider {
  private readonly pool: Pool;
  private readonly repos: Repositories;
  private readonly config: AppConfig;
  private readonly embeddingProvider: EmbeddingProvider;
  private readonly webSearchProvider: WebSearchProvider;
  private readonly fetcher: KnowledgeFetcher;
  private readonly retriever: HybridRetriever;
  private readonly ingestion: IngestionPipeline;
  private readonly researchEngine: ResearchEngine;
  private readonly eventBus: KnowledgeEngineDeps['eventBus'];
  private readonly logger?: KnowledgeEngineDeps['logger'];

  constructor(deps: KnowledgeEngineDeps) {
    this.pool = deps.pool;
    this.repos = deps.repos;
    this.config = deps.config;
    this.eventBus = deps.eventBus;
    this.logger = deps.logger;

    this.embeddingProvider = deps.embeddingProvider ?? buildEmbeddingProvider(deps.config);
    this.webSearchProvider = deps.webSearchProvider ?? new NullWebSearchProvider();
    this.fetcher = new KnowledgeFetcher({
      limits: {
        maxPageBytes: deps.config.knowledge.fetch.maxPageBytes,
        maxRedirects: deps.config.knowledge.fetch.maxRedirects,
        timeoutMs: deps.config.knowledge.fetch.timeoutMs,
        maxConcurrency: deps.config.knowledge.fetch.maxConcurrency,
        ratePerSourcePerMinute: deps.config.knowledge.fetch.ratePerSourcePerMinute,
        dailyFetchBudget: deps.config.knowledge.fetch.dailyFetchBudget,
        allowLoopback: deps.config.knowledge.fetch.allowLoopback,
      },
      objectStore: deps.objectStore,
      fetchImpl: deps.objectStore ? undefined : undefined,
    });

    const keywordIndex = new PostgresFtsKeywordIndex(this.pool);
    this.retriever = new HybridRetriever({
      keywordIndex,
      embeddingProvider: this.embeddingProvider,
      loadCandidates: (chunkIds) => this.loadCandidates(chunkIds),
      loadVectors: async (model) => {
        const rows = await this.repos.knowledgeEmbeddings.listVectors(model, 50_000);
        return rows.map((row) => ({ chunkId: row.chunk_id, embedding: row.embedding }));
      },
    });

    this.ingestion = new IngestionPipeline({
      repos: this.repos,
      fetcher: this.fetcher,
      embeddingProvider: this.embeddingProvider,
      limits: {
        chunkMinTokens: deps.config.knowledge.chunkMinTokens,
        chunkMaxTokens: deps.config.knowledge.chunkMaxTokens,
      },
      publish: (event) => this.eventBus.publish(event),
      logger: deps.logger,
    });

    this.researchEngine = new ResearchEngine({
      repos: this.repos,
      searchProvider: this.webSearchProvider,
      fetcher: this.fetcher,
      budget: {
        maxSearches: deps.config.knowledge.research.maxSearches,
        maxPages: deps.config.knowledge.research.maxPages,
        maxBytes: deps.config.knowledge.research.maxBytes,
        maxTimeMs: deps.config.knowledge.research.maxTimeMs,
        maxTokens: deps.config.knowledge.research.maxTokens,
      },
      publish: (event) => this.eventBus.publish(event),
      curatedDomains: CURATED_SOURCE_CATALOG.flatMap((entry) => entry.crawlPolicy.allowed_domains),
      logger: deps.logger,
    });
  }

  // ------------------------------------------------------------------ search

  /**
   * Hybrid retrieval with query cache + full audit (§15-§25, §65, §85).
   * The result packet is compact, provenance-carrying and token-bounded.
   */
  async search(request: KnowledgeSearchRequest, requestedBy = 'api'): Promise<KnowledgePacket> {
    // Index version covers embedding model + chunker generation (§65).
    const activeVersion = await this.repos.knowledgeVersions.findActive();
    const indexVersion = activeVersion
      ? `${activeVersion.embedding_model}:${activeVersion.embedding_version}:${activeVersion.chunker_max_tokens}`
      : 'bootstrap';

    const cacheKey = buildCacheKey({
      query: request.query,
      categories: request.categories,
      technologies: request.technologies,
      indexVersion,
      maxResults: request.max_results,
      maxTokens: request.max_tokens,
    });

    // Cache hit within TTL (§65): identical context/version serves the
    // stored packet without re-ranking.
    const cached = await this.repos.knowledgeCache.get(cacheKey);
    if (cached) {
      const queryRow = await this.repos.knowledgeQueries.insert({
        engagementId: request.engagement_id,
        hypothesisId: request.hypothesis_id,
        requestedBy,
        query: request.query,
        categories: request.categories,
        technologies: request.technologies,
        mode: request.mode,
        cacheKey,
      });
      await this.repos.knowledgeQueries.finalize(queryRow.id, {
        cacheHit: true,
        resultCount: (cached.packet['results'] as unknown[] | undefined)?.length ?? 0,
        tokensEstimate: Number(cached.packet['packet_tokens'] ?? 0),
      });
      // The stored packet carries cache_hit: false from its creation — the
      // response must reflect THIS request's hit.
      return { ...(cached.packet as Record<string, unknown>), cache_hit: true } as unknown as KnowledgePacket;
    }

    const queryRow = await this.repos.knowledgeQueries.insert({
      engagementId: request.engagement_id,
      hypothesisId: request.hypothesis_id,
      requestedBy,
      query: request.query,
      categories: request.categories,
      technologies: request.technologies,
      mode: request.mode,
      cacheKey,
    });
    await this.publishEvent('KNOWLEDGE_QUERY', request.engagement_id, {
      query_id: queryRow.id,
      query: request.query.slice(0, 300),
      categories: request.categories,
    });

    const outcome = await this.retriever.retrieve({
      query: request.query,
      limit: request.max_results * 3,
      categories: request.categories as SecurityTaxonomyCategory[],
      technologies: request.technologies,
      weights: {
        semantic: this.config.knowledge.weights.semantic,
        keyword: this.config.knowledge.weights.keyword,
        trust: this.config.knowledge.weights.trust,
        freshness: this.config.knowledge.weights.freshness,
        context: this.config.knowledge.weights.context,
        specificity: this.config.knowledge.weights.specificity,
        duplicatePenalty: this.config.knowledge.weights.duplicatePenalty,
      },
    });

    // Techniques matched for the same context (§46).
    const techniques = await matchTechniques({ repos: this.repos }, {
      query: request.query,
      categories: request.categories as SecurityTaxonomyCategory[],
      technologies: request.technologies,
      maxResults: 4,
    });

    const packet = buildPacket({
      queryId: queryRow.id,
      query: request.query,
      cacheHit: false,
      mode: request.mode,
      scored: outcome.scored,
      techniques,
      maxResults: request.max_results,
      maxTokens: request.max_tokens,
      notes:
        outcome.keywordHits === 0 && outcome.semanticHits === 0
          ? ['No matching local knowledge — consider knowledge.research for live research (§30)']
          : outcome.expandedTerms.length > 0
            ? [`Query expanded with: ${outcome.expandedTerms.slice(0, 4).join(', ')}`]
            : [],
      disagreements: detectDisagreements(outcome.scored.slice(0, 10)),
    });

    // Persist the scored candidates as retrieval results (§85, §97-§98).
    await this.repos.knowledgeResults.insertMany(
      outcome.scored.slice(0, 50).map((entry, rank) => ({
        queryId: queryRow.id,
        rank,
        chunkId: entry.chunk.chunkId,
        techniqueId: null,
        relevance: entry.relevance,
        keywordScore: entry.chunk.keywordScore,
        semanticScore: entry.chunk.semanticScore,
        trustScore: entry.trustScore,
        freshnessScore: entry.freshnessScore,
        finalScore: entry.finalScore,
        included: packet.results.some((result) => result.chunk_id === entry.chunk.chunkId),
      })),
    );
    await this.repos.knowledgeQueries.finalize(queryRow.id, {
      cacheHit: false,
      resultCount: packet.results.length,
      tokensEstimate: packet.packet_tokens,
    });
    await this.repos.knowledgeCache.put({
      cacheKey,
      queryId: queryRow.id,
      packet: packet as unknown as Record<string, unknown>,
      ttlMs: this.config.knowledge.cacheTtlMs,
    });
    await this.publishEvent('KNOWLEDGE_PACKET_CREATED', request.engagement_id, {
      query_id: queryRow.id,
      results: packet.results.length,
      tokens: packet.packet_tokens,
      truncated: packet.truncated,
    });
    return packet;
  }

  // ------------------------------------------------------------------- fetch

  /** Bounded live fetch + ingestion (§26, §34, §115). */
  async fetch(request: KnowledgeFetchRequest, _requestedBy = 'api'): Promise<IngestionOutcome> {
    const source = await this.resolveSourceForFetch(request.source_id, request.url);
    await this.publishEvent('WEB_DOCUMENT_FETCHED', request.engagement_id, {
      url: request.url.slice(0, 500),
      source_id: source.id,
    });
    return this.ingestion.ingest({
      sourceId: source.id,
      url: request.url,
      documentType: request.document_type,
      titleOverride: request.title_override,
      ctf: request.ctf,
    });
  }

  /** Ingest pre-fetched content (imports, tests, offline corpus). */
  async ingestRaw(input: {
    sourceId: string;
    url: string;
    bytes: Uint8Array;
    contentType: string | null;
    documentType?: 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF';
    titleOverride?: string;
  }): Promise<IngestionOutcome> {
    return this.ingestion.ingest({
      sourceId: input.sourceId,
      url: input.url,
      raw: { bytes: input.bytes, contentType: input.contentType },
      documentType: input.documentType,
      titleOverride: input.titleOverride,
    });
  }

  // ---------------------------------------------------------------- research

  async research(request: ResearchRequest, requestedBy = 'api'): Promise<ResearchResult> {
    return this.researchEngine.research(request, requestedBy);
  }

  /**
   * Direct web search surface for the knowledge.search_web tool (§33).
   * Bounded, trust-labelled, honest when no provider is configured.
   */
  async searchWeb(
    query: string,
    options: { maxResults: number; domainAllowlist?: string[]; domainDenylist?: string[] },
  ): Promise<{ results: Array<{ title: string; url: string; snippet: string; domain: string }>; note?: string }> {
    const outcome = await this.webSearchProvider.search(query, {
      maxResults: Math.min(Math.max(options.maxResults, 1), 10),
      domainAllowlist: options.domainAllowlist,
      domainDenylist: options.domainDenylist,
    });
    return { results: outcome.results, ...(outcome.note ? { note: outcome.note } : {}) };
  }

  // ----------------------------------------------------------- similar cases

  async similarCases(request: SimilarCaseRequest): Promise<SimilarCaseResult> {
    return similarCases(
      {
        repos: this.repos,
        retriever: this.retriever,
        ingest: (input) =>
          this.ingestion.ingest({
            sourceId: input.sourceId,
            url: input.url,
            raw: input.raw,
            titleOverride: input.titleOverride,
            ctf: input.ctf as never,
          }),
      },
      request,
    );
  }

  /** Ingest a CTF write-up into case memory (§39/§42). */
  async ingestCtfWriteup(input: {
    sourceId: string;
    url: string;
    challenge_name: string;
    event?: string | null;
    year?: number | null;
    category?: string | null;
    platform?: string | null;
    difficulty?: string | null;
    description: string;
    technique?: string | null;
    solution_summary?: string | null;
    body?: string;
  }): Promise<{ documentId: string; patternsStored: number }> {
    return ingestCtfWriteup(
      {
        repos: this.repos,
        ingest: (input) =>
          this.ingestion.ingest({
            sourceId: input.sourceId,
            url: input.url,
            raw: input.raw,
            titleOverride: input.titleOverride,
            ctf: input.ctf as never,
          }),
      },
      input,
    );
  }

  // ------------------------------------------------------------------- sync

  /**
   * Curated source synchronization (§29): seeds the catalog (idempotent),
   * activates the index version marker (§95) and (when entry paths are
   * configured) fetches the source's configured entries — bounded by
   * max_pages_per_sync (§27).
   */
  async sync(options: { sourceId?: string; seed?: boolean } = {}): Promise<{
    seeded: number;
    documents: number;
    skipped: string[];
  }> {
    let seeded = 0;
    if (options.seed !== false) {
      for (const entry of CURATED_SOURCE_CATALOG) {
        if (options.sourceId) continue;
        await this.repos.knowledgeSources.upsert({
          name: entry.name,
          type: entry.type,
          baseUrl: entry.baseUrl,
          trustLevel: entry.trustLevel,
          enabled: true,
          updateStrategy: entry.updateStrategy,
          crawlPolicy: {
            allowed_domains: entry.crawlPolicy.allowed_domains,
            blocked_domains: [],
            entry_paths: entry.crawlPolicy.entry_paths,
            respect_robots: true,
          },
          licenseNotes: entry.licenseNotes,
        });
        seeded += 1;
      }
    }

    // Activate the index version marker for the configured embedding model
    // (§95): one active row — model changes are explicit reindex events.
    const existing = await this.repos.knowledgeVersions.findActive();
    if (
      !existing ||
      existing.embedding_model !== this.embeddingProvider.model ||
      existing.chunker_max_tokens !== this.config.knowledge.chunkMaxTokens
    ) {
      await this.repos.knowledgeVersions.activate({
        embeddingModel: this.embeddingProvider.model,
        embeddingVersion: this.embeddingProvider.version,
        chunkerMinTokens: this.config.knowledge.chunkMinTokens,
        chunkerMaxTokens: this.config.knowledge.chunkMaxTokens,
        dimension: this.embeddingProvider.dimension,
        note: 'activated by source sync',
      });
    }

    let documents = 0;
    const skipped: string[] = [];
    const sources = options.sourceId
      ? [await this.repos.knowledgeSources.findById(options.sourceId)].filter(
          (source): source is KnowledgeSourceRecord => source !== null,
        )
      : await this.repos.knowledgeSources.list({ enabledOnly: true });

    const maxPages = this.config.knowledge.fetch.syncMaxPages;
    for (const source of sources) {
      const entries = source.crawl_policy.entry_paths.slice(0, maxPages);
      if (entries.length === 0) {
        skipped.push(`${source.name}: no entry paths configured (curated catalog — configure entries to sync)`);
        continue;
      }
      let fetched = 0;
      for (const entry of entries) {
        if (fetched >= maxPages) break;
        const url = entry.startsWith('http') ? entry : `${source.base_url.replace(/\/$/, '')}/${entry.replace(/^\//, '')}`;
        try {
          const outcome = await this.ingestion.ingest({ sourceId: source.id, url });
          if (outcome.ingestion_status !== 'FAILED') fetched += 1;
          documents += 1;
        } catch (error) {
          skipped.push(`${source.name}: ${error instanceof Error ? error.message : String(error)}`.slice(0, 200));
        }
      }
      await this.repos.knowledgeSources.markSynced(source.id);
      await this.publishEvent('KNOWLEDGE_SOURCE_SYNCED', null, {
        source_id: source.id,
        name: source.name,
        fetched,
      });
    }
    return { seeded, documents, skipped: skipped.slice(0, 20) };
  }

  // ------------------------------------------------------------------ status

  async status(): Promise<KnowledgeStatus> {
    const [sources, documents, chunks, embeddings, techniques, references, queries, researchTasks, recentQueries, cacheEntries] =
      await Promise.all([
        this.repos.knowledgeSources.count(),
        this.repos.knowledgeDocuments.count(),
        this.repos.knowledgeChunks.count(),
        this.repos.knowledgeEmbeddings.countByModel(this.embeddingProvider.model),
        this.repos.securityTechniques.count(),
        this.repos.knowledgeReferences.count(),
        this.repos.knowledgeQueries.count(),
        this.repos.researchTasks.count(),
        this.repos.knowledgeQueries.listRecent(200),
        this.repos.knowledgeCache.purgeExpired(),
      ]);
    return {
      sources,
      documents,
      chunks,
      embeddings,
      techniques,
      references,
      queries,
      researchTasks,
      embeddingModel: this.embeddingProvider.model,
      embeddingDimension: this.embeddingProvider.dimension,
      cache: { activeEntries: cacheEntries >= 0 ? cacheEntries : 0 },
      agentUtility: agentUtilityMetrics(recentQueries),
    };
  }

  // --------------------------------------------- leader knowledge context

  /**
   * KnowledgeContextProvider implementation (§87, §120): builds a compact
   * packet for the strategic leader from the engagement's active
   * hypotheses — trusted metadata + untrusted excerpts (§50 separation).
   */
  async buildKnowledgeContext(
    engagementId: string,
    options?: { maxTokens?: number },
  ): Promise<{
    trusted_summary: Record<string, unknown>;
    untrusted_detail: Record<string, unknown> | null;
  }> {
    const hypotheses = await this.repos.hypotheses.listByEngagement(engagementId, {
      statuses: ['PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED'],
    });
    if (hypotheses.length === 0) {
      return { trusted_summary: { note: 'no active hypotheses — no knowledge retrieval triggered (§123)' }, untrusted_detail: null };
    }
    // The top-priority hypothesis drives the query (§123: targeted
    // retrieval after an interesting observation, never on every request).
    const priority = [...hypotheses].sort((a, b) => b.priority - a.priority).slice(0, 2);
    const categories = [...new Set(priority.map((h) => h.type as string).filter((type) => type && type !== 'UNKNOWN' && type !== 'CTF_CLUE'))] as SecurityTaxonomyCategory[];
    const query = priority.map((h) => h.statement).join('; ').slice(0, 800) || 'web security testing strategy';
    const technologies: string[] = [];
    const endpoints = await this.repos.endpoints.listByEngagement(engagementId, { limit: 200 });
    void endpoints;

    const packet = await this.search(
      {
        query,
        engagement_id: engagementId,
        hypothesis_id: priority[0]?.id ?? null,
        categories: categories.slice(0, 4),
        technologies,
        mode: 'LOCAL_ONLY',
        max_results: 6,
        max_tokens: options?.maxTokens ?? this.config.knowledge.maxPacketTokens,
      },
      'leader-context',
    );

    return {
      trusted_summary: {
        knowledge_packet_present: packet.results.length > 0,
        query: packet.query,
        sources: packet.results.map((result) => ({
          name: result.source_name,
          trust: result.trust_level,
          relevance: result.relevance,
          corroborated: result.corroborated,
        })),
        techniques: packet.techniques.map((technique) => ({
          name: technique.name,
          category: technique.category,
          suggested_evidence: technique.suggested_evidence.slice(0, 3),
          alternative_explanations: technique.alternative_explanations.slice(0, 3),
        })),
        disagreements: packet.disagreements,
        packet_tokens: packet.packet_tokens,
        notes: packet.notes,
      },
      untrusted_detail:
        packet.results.length > 0
          ? {
              knowledge_excerpts: packet.results.map((result) => ({
                source: result.source_name,
                trust: result.trust_level,
                url: result.url,
                section: result.section,
                excerpt: result.content,
              })),
            }
          : null,
    };
  }

  // ---------------------------------------------------------------- helpers

  private async loadCandidates(chunkIds: string[]): Promise<CandidateChunk[]> {
    if (chunkIds.length === 0) return [];
    // Bounded IN-list queries in batches of 100.
    const out: CandidateChunk[] = [];
    for (let offset = 0; offset < chunkIds.length; offset += 100) {
      const batch = chunkIds.slice(offset, offset + 100);
      const result = await this.pool.query<Record<string, unknown>>(
        `SELECT c.id AS chunk_id, c.document_id, c.heading, c.section, c.kind, c.content, c.content_hash,
                d.source_id, d.title, d.canonical_url, d.trust_level, d.published_at, d.retrieved_at, d.metadata,
                s.name AS source_name
         FROM knowledge_chunks c
         JOIN knowledge_documents d ON d.id = c.document_id AND d.is_latest
         JOIN knowledge_sources s ON s.id = d.source_id
         WHERE c.id = ANY($1::text[])`,
        [batch],
      );
      for (const row of result.rows) {
        const metadata = (row['metadata'] ?? {}) as Record<string, unknown>;
        out.push({
          chunkId: row['chunk_id'] as string,
          documentId: row['document_id'] as string,
          sourceId: row['source_id'] as string,
          sourceName: row['source_name'] as string,
          url: row['canonical_url'] as string,
          title: row['title'] as string,
          heading: (row['heading'] as string | null) ?? null,
          section: (row['section'] as string | null) ?? null,
          kind: row['kind'] as string,
          content: row['content'] as string,
          trustLevel: row['trust_level'] as CandidateChunk['trustLevel'],
          publishedAt: (row['published_at'] as string | null) ?? null,
          retrievedAt: row['retrieved_at'] as string,
          contentHash: row['content_hash'] as string,
          technologies: (metadata['technologies'] as string[]) ?? [],
          categories: (metadata['security_categories'] as SecurityTaxonomyCategory[]) ?? [],
          keywordScore: 0,
          semanticScore: 0,
        });
      }
    }
    return out;
  }

  private async resolveSourceForFetch(sourceId: string | null, url: string): Promise<KnowledgeSourceRecord> {
    if (sourceId) {
      const source = await this.repos.knowledgeSources.findById(sourceId);
      if (!source) {
        throw Object.assign(new Error(`Knowledge source ${sourceId} not found`), { code: 'SOURCE_NOT_FOUND' });
      }
      return source;
    }
    // Auto-provision an UNTRUSTED live-web source for the domain (§32:
    // search results are UNTRUSTED_UNTIL_CLASSIFIED).
    const domain = new URL(url).hostname.toLowerCase();
    const existing = await this.repos.knowledgeSources.list({ limit: 500 });
    const match = existing.find((source) => source.type === 'LIVE_WEB' && source.base_url.includes(domain));
    if (match) return match;
    return this.repos.knowledgeSources.upsert({
      name: `Live web: ${domain}`,
      type: 'LIVE_WEB',
      baseUrl: `https://${domain}`,
      trustLevel: 'UNTRUSTED',
      enabled: true,
      updateStrategy: 'ON_DEMAND',
      crawlPolicy: { allowed_domains: [domain], blocked_domains: [], entry_paths: [], respect_robots: true },
      licenseNotes: null,
    });
  }

  private async publishEvent(
    type: PlatformEvent['type'],
    engagementId: string | null,
    payload: Record<string, unknown>,
  ): Promise<void> {
    const event: PlatformEvent = {
      type,
      engagement_id: engagementId ?? 'global',
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload,
      occurred_at: new Date().toISOString(),
      dedup_key: `${type.toLowerCase()}:${generateId('TRC')}`,
    };
    await this.eventBus.publish(event).catch(() => undefined);
  }
}

/** Build the configured embedding provider (§107: never hard-coded). */
export function buildEmbeddingProvider(config: AppConfig): EmbeddingProvider {
  switch (config.knowledge.embedding.provider) {
    case 'google': {
      const apiKey = process.env.GOOGLE_API_KEY ?? '';
      if (!apiKey) {
        // Honest degradation: keyword-only retrieval (§116).
        return new NoneEmbeddingProvider();
      }
      return new GoogleEmbeddingProvider({
        apiKey,
        model: config.knowledge.embedding.model,
        dimension: config.knowledge.embedding.dimension,
      });
    }
    case 'none':
      return new NoneEmbeddingProvider();
    case 'hash':
    default:
      return new HashingEmbeddingProvider(config.knowledge.embedding.model, config.knowledge.embedding.dimension);
  }
}
