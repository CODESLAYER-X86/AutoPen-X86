/**
 * Knowledge ingestion pipeline (spec Part 5 §115-§117, §25, §67, §94).
 *
 *   SOURCE → FETCH → RAW ARTIFACT → CONTENT TYPE → PARSER → SANITIZER →
 *   METADATA → SECTION EXTRACTION → CHUNKING → HASH → INDEX → EMBEDDING
 *
 * Every stage is observable (events + ingestion_status transitions) and
 * failure-isolated (§116): embedding failure keeps the document
 * keyword-searchable; parser failure retains the raw artifact and marks
 * the failure — the source is never lost.
 *
 * Idempotency: content-hash duplicate detection links URLs instead of
 * re-indexing (§67); a changed source at the same URL produces a new
 * VERSION and supersedes the old row without deleting history (§25).
 */
import type { KnowledgeSourceRecord, Repositories } from '@aegis/database';
import type { PlatformEvent } from '@aegis/contracts';
import { generateId } from '@aegis/shared';
import { detectDocumentKind, parseByKind, type ContentBlock, type ParsedDocument } from './parsers.js';
import { extractPdf } from './pdf.js';
import { extractMetadata } from './metadata.js';
import { chunkDocument } from './chunker.js';
import type { EmbeddingProvider } from './embeddings.js';
import type { KnowledgeFetcher } from './fetcher.js';
import { canonicalizeUrl, bytesHash, contentHash, domainOf } from './util.js';
import type { IngestionOutcome } from '@aegis/contracts';

export interface IngestDocumentInput {
  sourceId: string;
  url: string;
  /** Pre-fetched bytes (tests / HAR import); otherwise the fetcher runs. */
  raw?: { bytes: Uint8Array; contentType: string | null };
  documentType?: 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF';
  titleOverride?: string;
  ctf?: IngestionCtfInput;
  /** Structural fetch options (ETag revalidation, §66). */
  etag?: string | null;
  lastModified?: string | null;
}

export interface IngestionCtfInput {
  challenge_name: string;
  event?: string | null;
  year?: number | null;
  category?: string | null;
  platform?: string | null;
  difficulty?: string | null;
  description?: string;
  technique?: string | null;
  solution_summary?: string | null;
}

export interface IngestionDeps {
  repos: Repositories;
  fetcher?: KnowledgeFetcher;
  embeddingProvider: EmbeddingProvider;
  limits: { chunkMinTokens: number; chunkMaxTokens: number };
  publish: (event: PlatformEvent) => Promise<void>;
  logger?: { warn: (event: string, fields?: Record<string, unknown>) => void; info: (event: string, fields?: Record<string, unknown>) => void };
}

export class IngestionPipeline {
  constructor(private readonly deps: IngestionDeps) {}

  /**
   * Ingest one document end-to-end. Never throws for content-level
   * failures — the outcome records ingestion_status instead (§116).
   */
  async ingest(input: IngestDocumentInput): Promise<IngestionOutcome> {
    const { repos } = this.deps;
    const source = await repos.knowledgeSources.findById(input.sourceId);
    if (!source) {
      throw Object.assign(new Error(`Knowledge source ${input.sourceId} not found`), { code: 'SOURCE_NOT_FOUND' });
    }
    const canonicalUrl = canonicalizeUrl(input.url);

    // --- FETCH (+ raw artifact sealing) --------------------------------
    let bytes: Uint8Array;
    let contentType: string | null;
    let artifactKey: string | null = null;
    if (input.raw) {
      bytes = input.raw.bytes;
      contentType = input.raw.contentType;
    } else {
      if (!this.deps.fetcher) {
        throw Object.assign(new Error('No fetcher configured for this ingestion path'), {
          code: 'FETCHER_NOT_CONFIGURED',
        });
      }
      const policy = {
        allowedDomains: source.crawl_policy.allowed_domains,
        blockedDomains: source.crawl_policy.blocked_domains,
      };
      const fetched = await this.deps.fetcher.fetch(input.url, policy, {
        etag: input.etag ?? null,
        lastModified: input.lastModified ?? null,
      });
      bytes = fetched.bytes;
      contentType = fetched.contentType;
      artifactKey = fetched.artifactKey;
      if (bytes.length === 0 && fetched.notModified) {
        const existing = await repos.knowledgeDocuments.findLatestByUrl(canonicalUrl);
        if (existing) {
          return outcomeFor(existing.id, canonicalUrl, existing.content_hash, existing.version, false, null, 0, 0, existing.document_type, 'INDEXED', 0, 0, null);
        }
      }
    }

    // --- CONTENT TYPE → PARSER → SANITIZER -----------------------------
    const kind = input.documentType ?? detectDocumentKind(contentType, decodeHead(bytes));
    let parsed: ParsedDocument;
    let blocks: ContentBlock[];
    if (kind === 'PDF') {
      const extraction = extractPdf(bytes);
      parsed = { blocks: [], title: extraction.title, meta: {} };
      blocks = extraction.blocks;
    } else {
      const text = decodeUtf8(bytes);
      parsed = parseByKind(kind, text);
      blocks = parsed.blocks;
    }
    if (blocks.length === 0) {
      // Parser failure: retain the raw artifact + mark failure (§116).
      const failure = await this.persistDocument(input, source, canonicalUrl, kind, contentHash(''), 1, parsed, artifactKey, bytes, 'FAILED', 'parser produced no content blocks');
      return outcomeFor(failure.id, canonicalUrl, failure.content_hash, failure.version, true, null, 0, 0, kind, 'FAILED', 0, 0, 'parser produced no content blocks');
    }

    const fullText = blocks.map((b) => b.content).join('\n');
    const hash = contentHash(fullText);

    // --- DUPLICATE DETECTION (§67) ------------------------------------
    const duplicate = await repos.knowledgeDocuments.findLatestByHash(hash);
    const existingByUrl = await repos.knowledgeDocuments.findLatestByUrl(canonicalUrl);
    if (duplicate && duplicate.id !== existingByUrl?.id) {
      // Same content at another URL: link to the canonical document —
      // provenance of BOTH URLs is retained, no re-index (§67).
      const linked = await this.persistDocument(input, source, canonicalUrl, kind, hash, 1, parsed, artifactKey, bytes, 'INDEXED', null);
      return outcomeFor(linked.id, canonicalUrl, hash, 1, false, duplicate.id, 0, 0, kind, 'INDEXED', 0, 0, null);
    }

    // --- VERSIONING (§25) --------------------------------------------
    let version = 1;
    let newVersion = false;
    if (existingByUrl) {
      if (existingByUrl.content_hash === hash) {
        // Unchanged content: idempotent re-ingestion (§111). Chunks created
        // counts NEWLY created chunks — zero on the idempotent path.
        return outcomeFor(existingByUrl.id, canonicalUrl, hash, existingByUrl.version, false, null, 0, 0, existingByUrl.document_type, existingByUrl.ingestion_status, 0, 0, null);
      }
      version = existingByUrl.version + 1;
      newVersion = true;
    }

    // --- METADATA → CHUNKING → PERSIST --------------------------------
    const metadata = extractMetadata(fullText, parsed);
    const document = await this.persistDocument(
      input,
      source,
      canonicalUrl,
      kind,
      hash,
      version,
      parsed,
      artifactKey,
      bytes,
      'PARSED',
      null,
      metadata,
    );

    const chunked = chunkDocument({
      documentId: document.id,
      blocks,
      minTokens: this.deps.limits.chunkMinTokens,
      maxTokens: this.deps.limits.chunkMaxTokens,
    });
    // Re-chunking replaces chunks for THIS document only (§117).
    await repos.knowledgeChunks.deleteByDocument(document.id);
    const chunks = await repos.knowledgeChunks.insertMany(
      chunked.chunks.map((piece) => ({
        documentId: piece.documentId,
        heading: piece.heading,
        headingPath: piece.headingPath,
        section: piece.section,
        content: piece.content,
        tokenEstimate: piece.tokenEstimate,
        kind: piece.kind,
        codeLanguage: piece.codeLanguage,
        contentHash: piece.contentHash,
        parentChunkId: piece.parentChunkId,
      })),
    );
    await repos.knowledgeDocuments.setChunkCount(document.id, chunks.length);

    // --- INDEX: references (§57, §76) ---------------------------------
    const referenceRows = metadata.references.slice(0, 64).map((reference) => ({
      documentId: document.id,
      chunkId: null,
      techniqueId: null,
      hypothesisId: null,
      kind: reference.kind,
      value: reference.value,
      context: reference.context?.slice(0, 500) ?? null,
    }));
    const referencesExtracted = await repos.knowledgeReferences.insertMany(referenceRows);

    // --- EMBEDDING (best effort, §116) --------------------------------
    let embeddingsCreated = 0;
    let ingestionStatus: 'INDEXED' | 'EMBEDDING_FAILED' = 'INDEXED';
    if (this.deps.embeddingProvider.dimension > 0 && chunks.length > 0) {
      try {
        const embeddings = await this.deps.embeddingProvider.embed(
          chunks.map((chunk) => `${chunk.heading ? `${chunk.heading}\n` : ''}${chunk.content}`),
        );
        for (let i = 0; i < chunks.length && i < embeddings.length; i += 1) {
          await repos.knowledgeEmbeddings.upsert({
            chunkId: chunks[i]!.id,
            embedding: embeddings[i]!,
            embeddingModel: this.deps.embeddingProvider.model,
            embeddingVersion: this.deps.embeddingProvider.version,
            contentHash: chunks[i]!.content_hash,
          });
          embeddingsCreated += 1;
        }
      } catch (error) {
        ingestionStatus = 'EMBEDDING_FAILED';
        this.deps.logger?.warn('knowledge.embedding_failed', {
          document_id: document.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
    await repos.knowledgeDocuments.updateIngestion(document.id, ingestionStatus, null);

    // --- VERSION SUPERSESSION (§25) ------------------------------------
    if (existingByUrl) {
      await repos.knowledgeDocuments.supersede(existingByUrl.id, document.id);
    }

    await this.publishIndexedEvent(source.id, document.id, chunks.length, ingestionStatus);

    return outcomeFor(
      document.id,
      canonicalUrl,
      hash,
      version,
      newVersion,
      null,
      chunks.length,
      embeddingsCreated,
      kind,
      ingestionStatus,
      referencesExtracted,
      0,
      null,
      this.deps.embeddingProvider.dimension > 0 ? this.deps.embeddingProvider.model : null,
    );
  }

  private async persistDocument(
    input: IngestDocumentInput,
    source: { id: string; name: string; trust_level: KnowledgeSourceRecord['trust_level'] },
    canonicalUrl: string,
    kind: 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF',
    hash: string,
    version: number,
    parsed: ParsedDocument,
    artifactKey: string | null,
    bytes: Uint8Array,
    status: 'PENDING' | 'FETCHED' | 'PARSED' | 'INDEXED' | 'EMBEDDING_FAILED' | 'FAILED',
    error: string | null,
    metadataOverride?: ReturnType<typeof extractMetadata>,
  ) {
    const metadata =
      metadataOverride ??
      extractMetadata(parsed.blocks.map((b) => b.content).join('\n'), parsed);
    const title =
      input.titleOverride ??
      parsed.title ??
      domainOf(canonicalUrl) ??
      `Untitled document (${canonicalUrl.slice(0, 80)})`;
    const document = await this.deps.repos.knowledgeDocuments.insert({
      sourceId: source.id,
      title: title.slice(0, 500),
      canonicalUrl,
      contentHash: hash,
      documentType: kind,
      trustLevel: source.trust_level,
      version,
      publishedAt: metadata.publishedAt,
      metadata: {
        author: metadata.author,
        language: parsed.meta['lang'] ?? metadata.language,
        technologies: metadata.technologies,
        cve_refs: metadata.cveRefs,
        cwe_refs: metadata.cweRefs,
        owasp_refs: metadata.owaspRefs,
        http_methods: metadata.httpMethods,
        protocols: metadata.protocols,
        security_categories: metadata.securityCategories,
      },
      artifactRef: artifactKey,
      artifactHash: bytes.length > 0 ? bytesHash(bytes) : null,
      ctf: input.ctf
        ? {
            challenge_name: input.ctf.challenge_name,
            event: input.ctf.event ?? null,
            year: input.ctf.year ?? null,
            category: input.ctf.category ?? null,
            platform: input.ctf.platform ?? null,
            difficulty: input.ctf.difficulty ?? null,
            description: (input.ctf.description ?? '').slice(0, 4000),
            technique: input.ctf.technique ?? null,
            solution_summary: input.ctf.solution_summary ?? null,
          }
        : null,
      ingestionStatus: status,
      ingestionError: error,
    });
    return document;
  }

  private async publishIndexedEvent(
    sourceId: string,
    documentId: string,
    chunkCount: number,
    status: string,
  ): Promise<void> {
    const event: PlatformEvent = {
      type: status === 'EMBEDDING_FAILED' ? 'KNOWLEDGE_DOCUMENT_INDEXED' : 'KNOWLEDGE_DOCUMENT_INDEXED',
      engagement_id: 'global',
      task_id: null,
      trace_id: generateId('TRC'),
      actor_id: null,
      payload: { source_id: sourceId, document_id: documentId, chunks: chunkCount, status },
      occurred_at: new Date().toISOString(),
      dedup_key: `knowledge-indexed:${documentId}`,
    };
    await this.deps.publish(event).catch(() => undefined);
  }
}

function outcomeFor(
  documentId: string,
  canonicalUrl: string,
  hash: string,
  version: number,
  newVersion: boolean,
  duplicateOf: string | null,
  chunksCreated: number,
  embeddingsCreated: number,
  documentType: 'HTML' | 'MARKDOWN' | 'TXT' | 'JSON' | 'XML' | 'PDF',
  ingestionStatus: 'PENDING' | 'FETCHED' | 'PARSED' | 'INDEXED' | 'EMBEDDING_FAILED' | 'FAILED',
  referencesExtracted: number,
  techniquesExtracted: number,
  error: string | null,
  embeddingModel: string | null = null,
): IngestionOutcome {
  return {
    document_id: documentId,
    canonical_url: canonicalUrl,
    content_hash: hash,
    version,
    new_version: newVersion,
    duplicate_of: duplicateOf,
    document_type: documentType,
    chunks_created: chunksCreated,
    embeddings_created: embeddingsCreated,
    embedding_model: embeddingModel,
    ingestion_status: ingestionStatus,
    references_extracted: referencesExtracted,
    techniques_extracted: techniquesExtracted,
    error,
  };
}

function decodeHead(bytes: Uint8Array): string {
  return Buffer.from(bytes.subarray(0, 2048)).toString('utf8');
}

function decodeUtf8(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('utf8');
}
