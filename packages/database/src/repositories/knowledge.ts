/**
 * Part 5 knowledge repositories — sources, documents, chunks, embeddings,
 * index versions and the query cache (spec Part 5 §5, §8-§9, §14, §25, §65,
 * §67, §94-§95, §117).
 *
 * Structural notes:
 *  - Document versions are append-only: a changed source creates a new
 *    version and supersedes the previous row (§25) — never an overwrite.
 *  - Duplicate content across URLs links to the canonical document (§67).
 *  - Embedding rows carry model + version + dimension so an embedding-model
 *    change is an explicit reindex, never a silent vector mix (§95).
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  KnowledgeChunkRecord,
  KnowledgeCrawlPolicyRecord,
  KnowledgeCtfRecord,
  KnowledgeDocumentMetadataRecord,
  KnowledgeDocumentRecord,
  KnowledgeEmbeddingRecord,
  KnowledgeSourceRecord,
  KnowledgeVersionRecord,
} from '../types.js';
import { requireIso, type RepoBase } from './util.js';

// ---------------------------------------------------------------------------
// Sources.
// ---------------------------------------------------------------------------

export interface UpsertSourceInput {
  name: string;
  type: KnowledgeSourceRecord['type'];
  baseUrl: string;
  trustLevel: KnowledgeSourceRecord['trust_level'];
  enabled: boolean;
  updateStrategy: KnowledgeSourceRecord['update_strategy'];
  crawlPolicy: KnowledgeCrawlPolicyRecord;
  licenseNotes: string | null;
  configuration?: Record<string, unknown>;
}

const SOURCE_COLUMNS =
  'id, name, type, base_url, trust_level, enabled, update_strategy, crawl_policy, license_notes, last_synced, configuration, created_at, updated_at';

export class KnowledgeSourcesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  /** Idempotent upsert keyed by name — curated catalog seeding (§4). */
  async upsert(input: UpsertSourceInput): Promise<KnowledgeSourceRecord> {
    const result = await this.pool.query(
      `INSERT INTO knowledge_sources (id, name, type, base_url, trust_level, enabled, update_strategy, crawl_policy, license_notes, configuration)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10::jsonb)
       ON CONFLICT (name) DO UPDATE SET
         type = EXCLUDED.type,
         base_url = EXCLUDED.base_url,
         trust_level = EXCLUDED.trust_level,
         enabled = EXCLUDED.enabled,
         update_strategy = EXCLUDED.update_strategy,
         crawl_policy = EXCLUDED.crawl_policy,
         license_notes = EXCLUDED.license_notes,
         updated_at = now()
       RETURNING ${SOURCE_COLUMNS}`,
      [
        generateId('KSR'),
        input.name,
        input.type,
        input.baseUrl,
        input.trustLevel,
        input.enabled,
        input.updateStrategy,
        JSON.stringify(input.crawlPolicy),
        input.licenseNotes,
        JSON.stringify(input.configuration ?? {}),
      ],
    );
    return mapSource(result.rows[0]!);
  }

  async findById(id: string): Promise<KnowledgeSourceRecord | null> {
    const result = await this.pool.query(
      `SELECT ${SOURCE_COLUMNS} FROM knowledge_sources WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapSource(result.rows[0]) : null;
  }

  async list(options?: { enabledOnly?: boolean; limit?: number }): Promise<KnowledgeSourceRecord[]> {
    const limit = Math.min(Math.max(options?.limit ?? 200, 1), 500);
    const where = options?.enabledOnly ? 'WHERE enabled' : '';
    const result = await this.pool.query(
      `SELECT ${SOURCE_COLUMNS} FROM knowledge_sources ${where} ORDER BY name LIMIT $1`,
      [limit],
    );
    return result.rows.map(mapSource);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM knowledge_sources');
    return result.rows[0]!.n;
  }

  async markSynced(id: string): Promise<void> {
    await this.pool.query('UPDATE knowledge_sources SET last_synced = now(), updated_at = now() WHERE id = $1', [id]);
  }
}

// ---------------------------------------------------------------------------
// Documents (versioned, provenance-preserving).
// ---------------------------------------------------------------------------

export interface InsertDocumentInput {
  sourceId: string;
  title: string;
  canonicalUrl: string;
  contentHash: string;
  documentType: KnowledgeDocumentRecord['document_type'];
  trustLevel: KnowledgeDocumentRecord['trust_level'];
  version: number;
  publishedAt: string | null;
  metadata: KnowledgeDocumentMetadataRecord;
  artifactRef: string | null;
  artifactHash: string | null;
  ctf: KnowledgeCtfRecord | null;
  ingestionStatus?: KnowledgeDocumentRecord['ingestion_status'];
  ingestionError?: string | null;
}

const DOC_COLUMNS =
  'id, source_id, title, canonical_url, content_hash, document_type, trust_level, version, published_at, retrieved_at, updated_at, ingestion_status, ingestion_error, metadata, artifact_ref, artifact_hash, chunk_count, ctf, is_latest, superseded_by';

export class KnowledgeDocumentsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertDocumentInput): Promise<KnowledgeDocumentRecord> {
    const result = await this.pool.query(
      `INSERT INTO knowledge_documents
         (id, source_id, title, canonical_url, content_hash, document_type, trust_level, version,
          published_at, retrieved_at, updated_at, metadata, artifact_ref, artifact_hash, ctf, ingestion_status, ingestion_error)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now(), $10::jsonb, $11, $12, $13::jsonb, $14, $15)
       RETURNING ${DOC_COLUMNS}`,
      [
        generateId('KDC'),
        input.sourceId,
        input.title,
        input.canonicalUrl,
        input.contentHash,
        input.documentType,
        input.trustLevel,
        input.version,
        input.publishedAt,
        JSON.stringify(input.metadata ?? {}),
        input.artifactRef,
        input.artifactHash,
        input.ctf ? JSON.stringify(input.ctf) : null,
        input.ingestionStatus ?? 'PENDING',
        input.ingestionError ?? null,
      ],
    );
    return mapDocument(result.rows[0]!);
  }

  async findById(id: string): Promise<KnowledgeDocumentRecord | null> {
    const result = await this.pool.query(
      `SELECT ${DOC_COLUMNS} FROM knowledge_documents WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapDocument(result.rows[0]) : null;
  }

  async findLatestByUrl(canonicalUrl: string): Promise<KnowledgeDocumentRecord | null> {
    const result = await this.pool.query(
      `SELECT ${DOC_COLUMNS} FROM knowledge_documents WHERE canonical_url = $1 AND is_latest`,
      [canonicalUrl],
    );
    return result.rows[0] ? mapDocument(result.rows[0]) : null;
  }

  /** Duplicate detection across URLs (§67) — returns latest row with the hash. */
  async findLatestByHash(contentHash: string): Promise<KnowledgeDocumentRecord | null> {
    const result = await this.pool.query(
      `SELECT ${DOC_COLUMNS} FROM knowledge_documents WHERE content_hash = $1 AND is_latest LIMIT 1`,
      [contentHash],
    );
    return result.rows[0] ? mapDocument(result.rows[0]) : null;
  }

  async listVersions(canonicalUrl: string): Promise<KnowledgeDocumentRecord[]> {
    const result = await this.pool.query(
      `SELECT ${DOC_COLUMNS} FROM knowledge_documents WHERE canonical_url = $1 ORDER BY version DESC LIMIT 50`,
      [canonicalUrl],
    );
    return result.rows.map(mapDocument);
  }

  async listLatest(options?: {
    sourceId?: string;
    documentType?: KnowledgeDocumentRecord['document_type'];
    limit?: number;
  }): Promise<KnowledgeDocumentRecord[]> {
    const limit = Math.min(Math.max(options?.limit ?? 100, 1), 500);
    const clauses = ['is_latest'];
    const params: unknown[] = [];
    if (options?.sourceId) {
      params.push(options.sourceId);
      clauses.push(`source_id = $${params.length}`);
    }
    if (options?.documentType) {
      params.push(options.documentType);
      clauses.push(`document_type = $${params.length}`);
    }
    params.push(limit);
    const result = await this.pool.query(
      `SELECT ${DOC_COLUMNS} FROM knowledge_documents WHERE ${clauses.join(' AND ')}
       ORDER BY retrieved_at DESC LIMIT $${params.length}`,
      params,
    );
    return result.rows.map(mapDocument);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM knowledge_documents WHERE is_latest',
    );
    return result.rows[0]!.n;
  }

  async updateIngestion(
    id: string,
    status: KnowledgeDocumentRecord['ingestion_status'],
    error: string | null,
  ): Promise<void> {
    await this.pool.query(
      'UPDATE knowledge_documents SET ingestion_status = $1, ingestion_error = $2, updated_at = now() WHERE id = $3',
      [status, error, id],
    );
  }

  async setChunkCount(id: string, chunkCount: number): Promise<void> {
    await this.pool.query(
      'UPDATE knowledge_documents SET chunk_count = $1, updated_at = now() WHERE id = $2',
      [chunkCount, id],
    );
  }

  /** Version history: old row superseded, new row becomes latest (§25). */
  async supersede(oldId: string, newId: string): Promise<void> {
    await this.pool.query(
      `UPDATE knowledge_documents SET is_latest = false, superseded_by = $1, updated_at = now() WHERE id = $2`,
      [newId, oldId],
    );
  }
}

// ---------------------------------------------------------------------------
// Chunks.
// ---------------------------------------------------------------------------

export interface InsertChunkInput {
  documentId: string;
  heading: string | null;
  headingPath: string[];
  section: string | null;
  content: string;
  tokenEstimate: number;
  kind: KnowledgeChunkRecord['kind'];
  codeLanguage: string | null;
  contentHash: string;
  parentChunkId: string | null;
}

const CHUNK_COLUMNS =
  'id, document_id, heading, heading_path, section, content, token_estimate, kind, code_language, content_hash, parent_chunk_id, created_at';

export class KnowledgeChunksRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insertMany(inputs: InsertChunkInput[]): Promise<KnowledgeChunkRecord[]> {
    if (inputs.length === 0) return [];
    const rows: KnowledgeChunkRecord[] = [];
    // Bounded batches keep parameter counts under PG limits.
    for (let offset = 0; offset < inputs.length; offset += 50) {
      const batch = inputs.slice(offset, offset + 50);
      const values: string[] = [];
      const params: unknown[] = [];
      let i = 0;
      for (const input of batch) {
        const base = i * 11;
        values.push(
          `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, $${base + 8}, $${base + 9}::jsonb, $${base + 10}, $${base + 11})`,
        );
        params.push(
          generateId('KCK'),
          input.documentId,
          input.heading,
          input.section,
          input.content,
          input.tokenEstimate,
          input.kind,
          input.codeLanguage,
          JSON.stringify(input.headingPath),
          input.contentHash,
          input.parentChunkId,
        );
        i += 1;
      }
      const result = await this.pool.query(
        `INSERT INTO knowledge_chunks
           (id, document_id, heading, section, content, token_estimate, kind, code_language, heading_path, content_hash, parent_chunk_id)
         VALUES ${values.join(', ')}
         RETURNING ${CHUNK_COLUMNS}`,
        params,
      );
      rows.push(...result.rows.map(mapChunk));
    }
    return rows;
  }

  async findById(id: string): Promise<KnowledgeChunkRecord | null> {
    const result = await this.pool.query(`SELECT ${CHUNK_COLUMNS} FROM knowledge_chunks WHERE id = $1`, [id]);
    return result.rows[0] ? mapChunk(result.rows[0]) : null;
  }

  async findByDocument(documentId: string): Promise<KnowledgeChunkRecord[]> {
    const result = await this.pool.query(
      `SELECT ${CHUNK_COLUMNS} FROM knowledge_chunks WHERE document_id = $1 ORDER BY created_at, id`,
      [documentId],
    );
    return result.rows.map(mapChunk);
  }

  /** Re-chunking path (§117): drop a document's chunks before re-inserting. */
  async deleteByDocument(documentId: string): Promise<void> {
    await this.pool.query('DELETE FROM knowledge_chunks WHERE document_id = $1', [documentId]);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM knowledge_chunks');
    return result.rows[0]!.n;
  }

  /**
   * Keyword search joined with document + source metadata (retrieval and
   * local-research surface). Returns bounded rows for packet assembly.
   */
  async searchJoined(
    query: string,
    limit: number,
  ): Promise<
    Array<{
      chunk_id: string;
      document_id: string;
      source_id: string;
      source_name: string;
      url: string;
      title: string;
      heading: string | null;
      section: string | null;
      kind: string;
      content: string;
      trust_level: string;
      published_at: string | null;
      retrieved_at: string;
      content_hash: string;
      metadata: Record<string, unknown>;
      score: number;
    }>
  > {
    const trimmed = query.trim().slice(0, 500);
    if (!trimmed) return [];
    const result = await this.pool.query<Record<string, unknown>>(
      `SELECT c.id AS chunk_id, c.document_id, c.heading, c.section, c.kind, c.content, c.content_hash,
              d.source_id, d.title, d.canonical_url, d.trust_level, d.published_at, d.retrieved_at, d.metadata,
              s.name AS source_name,
              ts_rank(to_tsvector('english', coalesce(c.heading, '') || ' ' || c.content), q) AS score
       FROM knowledge_chunks c
       JOIN knowledge_documents d ON d.id = c.document_id AND d.is_latest
       JOIN knowledge_sources s ON s.id = d.source_id
       CROSS JOIN websearch_to_tsquery('english', $1) AS q
       WHERE to_tsvector('english', coalesce(c.heading, '') || ' ' || c.content) @@ q
       ORDER BY score DESC, c.id
       LIMIT $2`,
      [trimmed, Math.min(Math.max(limit, 1), 100)],
    );
    return result.rows.map((row) => ({
      chunk_id: row['chunk_id'] as string,
      document_id: row['document_id'] as string,
      source_id: row['source_id'] as string,
      source_name: row['source_name'] as string,
      url: row['canonical_url'] as string,
      title: row['title'] as string,
      heading: (row['heading'] as string | null) ?? null,
      section: (row['section'] as string | null) ?? null,
      kind: row['kind'] as string,
      content: row['content'] as string,
      trust_level: row['trust_level'] as string,
      published_at: row['published_at'] ? requireIso(row['published_at'] as Date) : null,
      retrieved_at: requireIso(row['retrieved_at'] as Date),
      content_hash: row['content_hash'] as string,
      metadata: (row['metadata'] ?? {}) as Record<string, unknown>,
      score: Number(row['score']),
    }));
  }
}

// ---------------------------------------------------------------------------
// Embeddings.
// ---------------------------------------------------------------------------

export interface UpsertEmbeddingInput {
  chunkId: string;
  embedding: number[];
  embeddingModel: string;
  embeddingVersion: number;
  contentHash: string;
}

export class KnowledgeEmbeddingsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertEmbeddingInput): Promise<KnowledgeEmbeddingRecord> {
    const result = await this.pool.query(
      `INSERT INTO knowledge_chunk_embeddings (chunk_id, embedding, embedding_model, embedding_version, dimension, content_hash)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (chunk_id) DO UPDATE SET
         embedding = EXCLUDED.embedding,
         embedding_model = EXCLUDED.embedding_model,
         embedding_version = EXCLUDED.embedding_version,
         dimension = EXCLUDED.dimension,
         content_hash = EXCLUDED.content_hash,
         created_at = now()
       RETURNING chunk_id, embedding, embedding_model, embedding_version, dimension, content_hash, created_at`,
      [
        input.chunkId,
        input.embedding,
        input.embeddingModel,
        input.embeddingVersion,
        input.embedding.length,
        input.contentHash,
      ],
    );
    return result.rows[0]! as unknown as KnowledgeEmbeddingRecord;
  }

  async countByModel(embeddingModel: string): Promise<number> {
    const result = await this.pool.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM knowledge_chunk_embeddings WHERE embedding_model = $1',
      [embeddingModel],
    );
    return result.rows[0]!.n;
  }

  /** Bounded vector scan surface: chunk_id + vector pairs for cosine ranking. */
  async listVectors(embeddingModel: string, limit: number): Promise<
    Array<{ chunk_id: string; embedding: number[] }>
  > {
    const result = await this.pool.query<{ chunk_id: string; embedding: number[] }>(
      `SELECT chunk_id, embedding FROM knowledge_chunk_embeddings
       WHERE embedding_model = $1 ORDER BY chunk_id LIMIT $2`,
      [embeddingModel, Math.min(Math.max(limit, 1), 50_000)],
    );
    return result.rows;
  }
}

// ---------------------------------------------------------------------------
// Index versions + query cache.
// ---------------------------------------------------------------------------

export class KnowledgeVersionsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async findActive(): Promise<KnowledgeVersionRecord | null> {
    const result = await this.pool.query(
      `SELECT id, embedding_model, embedding_version, chunker_min_tokens, chunker_max_tokens, dimension, active, note, created_at
       FROM knowledge_versions WHERE active LIMIT 1`,
    );
    return result.rows[0] ? mapVersion(result.rows[0]) : null;
  }

  /** Activates a version row; only one row may be active at a time (§95). */
  async activate(input: {
    embeddingModel: string;
    embeddingVersion: number;
    chunkerMinTokens: number;
    chunkerMaxTokens: number;
    dimension: number;
    note?: string | null;
  }): Promise<KnowledgeVersionRecord> {
    const id = generateId('KVR');
    const result = await this.pool.query(
      `WITH deactivated AS (
         UPDATE knowledge_versions SET active = false WHERE active RETURNING id
       )
       INSERT INTO knowledge_versions (id, embedding_model, embedding_version, chunker_min_tokens, chunker_max_tokens, dimension, active, note)
       VALUES ($1, $2, $3, $4, $5, $6, true, $7)
       RETURNING id, embedding_model, embedding_version, chunker_min_tokens, chunker_max_tokens, dimension, active, note, created_at`,
      [
        id,
        input.embeddingModel,
        input.embeddingVersion,
        input.chunkerMinTokens,
        input.chunkerMaxTokens,
        input.dimension,
        input.note ?? null,
      ],
    );
    return mapVersion(result.rows[0]!);
  }
}

export class KnowledgeCacheRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async get(cacheKey: string): Promise<{ packet: Record<string, unknown>; created_at: string } | null> {
    const result = await this.pool.query<{ packet: Record<string, unknown>; created_at: Date }>(
      'SELECT packet, created_at FROM knowledge_cache WHERE cache_key = $1 AND expires_at > now()',
      [cacheKey],
    );
    if (!result.rows[0]) return null;
    return { packet: result.rows[0].packet, created_at: requireIso(result.rows[0].created_at) };
  }

  async put(input: {
    cacheKey: string;
    queryId: string;
    packet: Record<string, unknown>;
    ttlMs: number;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO knowledge_cache (cache_key, query_id, packet, expires_at)
       VALUES ($1, $2, $3::jsonb, now() + ($4::bigint / 1000.0) * interval '1 second')
       ON CONFLICT (cache_key) DO UPDATE SET
         query_id = EXCLUDED.query_id,
         packet = EXCLUDED.packet,
         created_at = now(),
         expires_at = EXCLUDED.expires_at`,
      [input.cacheKey, input.queryId, JSON.stringify(input.packet), Math.round(input.ttlMs)],
    );
  }

  async purgeExpired(): Promise<number> {
    const result = await this.pool.query('DELETE FROM knowledge_cache WHERE expires_at <= now()');
    return result.rowCount ?? 0;
  }
}

// ---------------------------------------------------------------------------
// Row mappers.
// ---------------------------------------------------------------------------

type SourceRow = Record<string, unknown>;

function mapSource(row: SourceRow): KnowledgeSourceRecord {
  const crawl = (row['crawl_policy'] ?? {}) as Record<string, unknown>;
  return {
    id: row['id'] as string,
    name: row['name'] as string,
    type: row['type'] as KnowledgeSourceRecord['type'],
    base_url: row['base_url'] as string,
    trust_level: row['trust_level'] as KnowledgeSourceRecord['trust_level'],
    enabled: row['enabled'] as boolean,
    update_strategy: row['update_strategy'] as KnowledgeSourceRecord['update_strategy'],
    crawl_policy: {
      allowed_domains: (crawl['allowed_domains'] as string[]) ?? [],
      blocked_domains: (crawl['blocked_domains'] as string[]) ?? [],
      entry_paths: (crawl['entry_paths'] as string[]) ?? [],
      respect_robots: (crawl['respect_robots'] as boolean) ?? true,
    },
    license_notes: (row['license_notes'] as string | null) ?? null,
    last_synced: row['last_synced'] ? requireIso(row['last_synced'] as Date) : null,
    configuration: (row['configuration'] ?? {}) as Record<string, unknown>,
    created_at: requireIso(row['created_at'] as Date),
    updated_at: requireIso(row['updated_at'] as Date),
  };
}

function mapDocument(row: SourceRow): KnowledgeDocumentRecord {
  return {
    id: row['id'] as string,
    source_id: row['source_id'] as string,
    title: row['title'] as string,
    canonical_url: row['canonical_url'] as string,
    content_hash: row['content_hash'] as string,
    document_type: row['document_type'] as KnowledgeDocumentRecord['document_type'],
    trust_level: row['trust_level'] as KnowledgeDocumentRecord['trust_level'],
    version: row['version'] as number,
    published_at: row['published_at'] ? requireIso(row['published_at'] as Date) : null,
    retrieved_at: requireIso(row['retrieved_at'] as Date),
    updated_at: requireIso(row['updated_at'] as Date),
    ingestion_status: row['ingestion_status'] as KnowledgeDocumentRecord['ingestion_status'],
    ingestion_error: (row['ingestion_error'] as string | null) ?? null,
    metadata: (row['metadata'] ?? {}) as KnowledgeDocumentMetadataRecord,
    artifact_ref: (row['artifact_ref'] as string | null) ?? null,
    artifact_hash: (row['artifact_hash'] as string | null) ?? null,
    chunk_count: row['chunk_count'] as number,
    ctf: (row['ctf'] as KnowledgeCtfRecord | null) ?? null,
    is_latest: row['is_latest'] as boolean,
    superseded_by: (row['superseded_by'] as string | null) ?? null,
  };
}

function mapChunk(row: SourceRow): KnowledgeChunkRecord {
  return {
    id: row['id'] as string,
    document_id: row['document_id'] as string,
    heading: (row['heading'] as string | null) ?? null,
    heading_path: (row['heading_path'] as string[]) ?? [],
    section: (row['section'] as string | null) ?? null,
    content: row['content'] as string,
    token_estimate: row['token_estimate'] as number,
    kind: row['kind'] as KnowledgeChunkRecord['kind'],
    code_language: (row['code_language'] as string | null) ?? null,
    content_hash: row['content_hash'] as string,
    parent_chunk_id: (row['parent_chunk_id'] as string | null) ?? null,
    created_at: requireIso(row['created_at'] as Date),
  };
}

function mapVersion(row: SourceRow): KnowledgeVersionRecord {
  return {
    id: row['id'] as string,
    embedding_model: row['embedding_model'] as string,
    embedding_version: row['embedding_version'] as number,
    chunker_min_tokens: row['chunker_min_tokens'] as number,
    chunker_max_tokens: row['chunker_max_tokens'] as number,
    dimension: row['dimension'] as number,
    active: row['active'] as boolean,
    note: (row['note'] as string | null) ?? null,
    created_at: requireIso(row['created_at'] as Date),
  };
}
