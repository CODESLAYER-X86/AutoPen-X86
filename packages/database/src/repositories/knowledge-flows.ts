/**
 * Part 5 knowledge flow repositories — structured security techniques,
 * extracted references, query audit rows, retrieval results, research
 * tasks and research sources (spec Part 5 §43, §57, §59, §71-§72, §85).
 */
import type { Pool } from 'pg';
import { generateId } from '@aegis/shared';
import type {
  KnowledgeQueryRecord,
  KnowledgeReferenceRecord,
  KnowledgeResultRecord,
  ResearchSourceRecord,
  ResearchTaskRecord,
  SecurityTechniqueRecord,
} from '../types.js';
import { requireIso, type RepoBase } from './util.js';

// ---------------------------------------------------------------------------
// Security techniques (spec §43).
// ---------------------------------------------------------------------------

export interface UpsertTechniqueInput {
  name: string;
  category: SecurityTechniqueRecord['category'];
  description: string;
  preconditions: string[];
  signals: string[];
  testPatterns: string[];
  verificationPatterns: string[];
  falsePositiveConditions: string[];
  sourceIds: string[];
  confidence: number;
}

const TECHNIQUE_COLUMNS =
  'id, name, category, description, preconditions, signals, test_patterns, verification_patterns, false_positive_conditions, source_ids, confidence, created_at, updated_at';

export class SecurityTechniquesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async upsert(input: UpsertTechniqueInput): Promise<SecurityTechniqueRecord> {
    const result = await this.pool.query(
      `INSERT INTO security_techniques
         (id, name, category, description, preconditions, signals, test_patterns, verification_patterns, false_positive_conditions, source_ids, confidence)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11)
       ON CONFLICT (name) DO UPDATE SET
         category = EXCLUDED.category,
         description = EXCLUDED.description,
         preconditions = EXCLUDED.preconditions,
         signals = EXCLUDED.signals,
         test_patterns = EXCLUDED.test_patterns,
         verification_patterns = EXCLUDED.verification_patterns,
         false_positive_conditions = EXCLUDED.false_positive_conditions,
         source_ids = EXCLUDED.source_ids,
         confidence = EXCLUDED.confidence,
         updated_at = now()
       RETURNING ${TECHNIQUE_COLUMNS}`,
      [
        generateId('KTF'),
        input.name,
        input.category,
        input.description,
        JSON.stringify(input.preconditions),
        JSON.stringify(input.signals),
        JSON.stringify(input.testPatterns),
        JSON.stringify(input.verificationPatterns),
        JSON.stringify(input.falsePositiveConditions),
        JSON.stringify(input.sourceIds),
        input.confidence,
      ],
    );
    return mapTechnique(result.rows[0]!);
  }

  async findById(id: string): Promise<SecurityTechniqueRecord | null> {
    const result = await this.pool.query(
      `SELECT ${TECHNIQUE_COLUMNS} FROM security_techniques WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapTechnique(result.rows[0]) : null;
  }

  async listByCategory(category: string, limit = 100): Promise<SecurityTechniqueRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TECHNIQUE_COLUMNS} FROM security_techniques WHERE category = $1
       ORDER BY confidence DESC, name LIMIT $2`,
      [category, Math.min(Math.max(limit, 1), 500)],
    );
    return result.rows.map(mapTechnique);
  }

  async list(limit = 500): Promise<SecurityTechniqueRecord[]> {
    const result = await this.pool.query(
      `SELECT ${TECHNIQUE_COLUMNS} FROM security_techniques ORDER BY category, name LIMIT $1`,
      [Math.min(Math.max(limit, 1), 1000)],
    );
    return result.rows.map(mapTechnique);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM security_techniques');
    return result.rows[0]!.n;
  }
}

// ---------------------------------------------------------------------------
// Extracted references (spec §57, §59, §76).
// ---------------------------------------------------------------------------

export interface InsertReferenceInput {
  documentId: string | null;
  chunkId: string | null;
  techniqueId: string | null;
  hypothesisId: string | null;
  kind: KnowledgeReferenceRecord['kind'];
  value: string;
  context: string | null;
}

export class KnowledgeReferencesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insertMany(inputs: InsertReferenceInput[]): Promise<number> {
    if (inputs.length === 0) return 0;
    // Simple loop insert: reference counts are small and this keeps the code
    // obvious (correctness over batch micro-optimisation).
    let inserted = 0;
    for (const input of inputs.slice(0, 200)) {
      await this.pool.query(
        `INSERT INTO knowledge_references (id, document_id, chunk_id, technique_id, hypothesis_id, kind, value, context)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          generateId('KRF'),
          input.documentId,
          input.chunkId,
          input.techniqueId,
          input.hypothesisId,
          input.kind,
          input.value,
          input.context,
        ],
      );
      inserted += 1;
    }
    return inserted;
  }

  async findByDocument(documentId: string): Promise<KnowledgeReferenceRecord[]> {
    const result = await this.pool.query(
      `SELECT id, document_id, chunk_id, technique_id, hypothesis_id, kind, value, context, created_at
       FROM knowledge_references WHERE document_id = $1 ORDER BY kind, value LIMIT 500`,
      [documentId],
    );
    return result.rows.map(mapReference);
  }

  async findByValue(kind: string, value: string): Promise<KnowledgeReferenceRecord[]> {
    const result = await this.pool.query(
      `SELECT id, document_id, chunk_id, technique_id, hypothesis_id, kind, value, context, created_at
       FROM knowledge_references WHERE kind = $1 AND value = $2 LIMIT 100`,
      [kind, value],
    );
    return result.rows.map(mapReference);
  }

  async findByHypothesis(hypothesisId: string): Promise<KnowledgeReferenceRecord[]> {
    const result = await this.pool.query(
      `SELECT id, document_id, chunk_id, technique_id, hypothesis_id, kind, value, context, created_at
       FROM knowledge_references WHERE hypothesis_id = $1 LIMIT 100`,
      [hypothesisId],
    );
    return result.rows.map(mapReference);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM knowledge_references');
    return result.rows[0]!.n;
  }
}

// ---------------------------------------------------------------------------
// Query audit (spec §65, §85).
// ---------------------------------------------------------------------------

export interface InsertQueryInput {
  engagementId: string | null;
  hypothesisId: string | null;
  requestedBy: string;
  query: string;
  categories: string[];
  technologies: string[];
  mode: KnowledgeQueryRecord['mode'];
  cacheKey: string | null;
}

export class KnowledgeQueriesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertQueryInput): Promise<KnowledgeQueryRecord> {
    const id = generateId('KQR');
    const result = await this.pool.query(
      `INSERT INTO knowledge_queries
         (id, engagement_id, hypothesis_id, requested_by, query, categories, technologies, mode, cache_key)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9)
       RETURNING id, engagement_id, hypothesis_id, requested_by, query, categories, technologies, mode, cache_key, cache_hit, result_count, tokens_estimate, created_at`,
      [
        id,
        input.engagementId,
        input.hypothesisId,
        input.requestedBy,
        input.query,
        JSON.stringify(input.categories),
        JSON.stringify(input.technologies),
        input.mode,
        input.cacheKey,
      ],
    );
    return mapQuery(result.rows[0]!);
  }

  async finalize(id: string, input: { cacheHit: boolean; resultCount: number; tokensEstimate: number }): Promise<void> {
    await this.pool.query(
      'UPDATE knowledge_queries SET cache_hit = $1, result_count = $2, tokens_estimate = $3 WHERE id = $4',
      [input.cacheHit, input.resultCount, input.tokensEstimate, id],
    );
  }

  async findRecentByCacheKey(cacheKey: string, withinMs: number): Promise<KnowledgeQueryRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, hypothesis_id, requested_by, query, categories, technologies, mode, cache_key, cache_hit, result_count, tokens_estimate, created_at
       FROM knowledge_queries
       WHERE cache_key = $1 AND created_at > now() - ($2::bigint / 1000.0) * interval '1 second'
       ORDER BY created_at DESC LIMIT 1`,
      [cacheKey, Math.round(withinMs)],
    );
    return result.rows[0] ? mapQuery(result.rows[0]) : null;
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<KnowledgeQueryRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, hypothesis_id, requested_by, query, categories, technologies, mode, cache_key, cache_hit, result_count, tokens_estimate, created_at
       FROM knowledge_queries WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapQuery);
  }

  async listRecent(limit = 50): Promise<KnowledgeQueryRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, hypothesis_id, requested_by, query, categories, technologies, mode, cache_key, cache_hit, result_count, tokens_estimate, created_at
       FROM knowledge_queries ORDER BY created_at DESC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapQuery);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM knowledge_queries');
    return result.rows[0]!.n;
  }
}

// ---------------------------------------------------------------------------
// Retrieval results (spec §85, §97-§98).
// ---------------------------------------------------------------------------

export interface InsertResultInput {
  queryId: string;
  rank: number;
  chunkId: string | null;
  techniqueId: string | null;
  relevance: number;
  keywordScore: number;
  semanticScore: number;
  trustScore: number;
  freshnessScore: number;
  finalScore: number;
  included: boolean;
}

export class KnowledgeResultsRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insertMany(inputs: InsertResultInput[]): Promise<void> {
    if (inputs.length === 0) return;
    for (const input of inputs.slice(0, 200)) {
      await this.pool.query(
        `INSERT INTO knowledge_results
           (id, query_id, rank, chunk_id, technique_id, relevance, keyword_score, semantic_score, trust_score, freshness_score, final_score, included)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [
          generateId('KRT'),
          input.queryId,
          input.rank,
          input.chunkId,
          input.techniqueId,
          input.relevance,
          input.keywordScore,
          input.semanticScore,
          input.trustScore,
          input.freshnessScore,
          input.finalScore,
          input.included,
        ],
      );
    }
  }

  async findByQuery(queryId: string): Promise<KnowledgeResultRecord[]> {
    const result = await this.pool.query(
      `SELECT id, query_id, rank, chunk_id, technique_id, relevance, keyword_score, semantic_score, trust_score, freshness_score, final_score, included, created_at
       FROM knowledge_results WHERE query_id = $1 ORDER BY rank LIMIT 200`,
      [queryId],
    );
    return result.rows.map(mapResult);
  }
}

// ---------------------------------------------------------------------------
// Research tasks + sources (spec §71-§72, §83, §85).
// ---------------------------------------------------------------------------

export interface InsertResearchTaskInput {
  engagementId: string | null;
  requestedBy: string;
  question: string;
  hypothesis: string | null;
  requiredEvidence: string[];
  sourceConstraints: string[];
  mode: ResearchTaskRecord['mode'];
  maxSources: number;
  maxTokens: number;
  deadlineMs: number;
}

export class ResearchTasksRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertResearchTaskInput): Promise<ResearchTaskRecord> {
    const id = generateId('RSC');
    const result = await this.pool.query(
      `INSERT INTO research_tasks
         (id, engagement_id, requested_by, question, hypothesis, required_evidence, source_constraints, mode, max_sources, max_tokens, deadline_ms)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10, $11)
       RETURNING id, engagement_id, requested_by, question, hypothesis, required_evidence, source_constraints, mode, status, max_sources, max_tokens, deadline_ms, started_at, completed_at, error, result, tokens_consumed, created_at`,
      [
        id,
        input.engagementId,
        input.requestedBy,
        input.question,
        input.hypothesis,
        JSON.stringify(input.requiredEvidence),
        JSON.stringify(input.sourceConstraints),
        input.mode,
        input.maxSources,
        input.maxTokens,
        input.deadlineMs,
      ],
    );
    return mapResearchTask(result.rows[0]!);
  }

  async findById(id: string): Promise<ResearchTaskRecord | null> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, requested_by, question, hypothesis, required_evidence, source_constraints, mode, status, max_sources, max_tokens, deadline_ms, started_at, completed_at, error, result, tokens_consumed, created_at
       FROM research_tasks WHERE id = $1`,
      [id],
    );
    return result.rows[0] ? mapResearchTask(result.rows[0]) : null;
  }

  async update(
    id: string,
    patch: {
      status?: ResearchTaskRecord['status'];
      startedAt?: string | null;
      completedAt?: string | null;
      error?: string | null;
      result?: Record<string, unknown> | null;
      tokensConsumed?: number;
    },
  ): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    const push = (column: string, value: unknown) => {
      params.push(value);
      sets.push(`${column} = $${params.length}`);
    };
    if (patch.status !== undefined) push('status', patch.status);
    if (patch.startedAt !== undefined) push('started_at', patch.startedAt);
    if (patch.completedAt !== undefined) push('completed_at', patch.completedAt);
    if (patch.error !== undefined) push('error', patch.error);
    if (patch.result !== undefined) push('result', patch.result ? JSON.stringify(patch.result) : null);
    if (patch.tokensConsumed !== undefined) push('tokens_consumed', patch.tokensConsumed);
    if (sets.length === 0) return;
    push('id', id);
    await this.pool.query(`UPDATE research_tasks SET ${sets.join(', ')} WHERE id = $${params.length}`, params);
  }

  async listByEngagement(engagementId: string, limit = 50): Promise<ResearchTaskRecord[]> {
    const result = await this.pool.query(
      `SELECT id, engagement_id, requested_by, question, hypothesis, required_evidence, source_constraints, mode, status, max_sources, max_tokens, deadline_ms, started_at, completed_at, error, result, tokens_consumed, created_at
       FROM research_tasks WHERE engagement_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [engagementId, Math.min(Math.max(limit, 1), 200)],
    );
    return result.rows.map(mapResearchTask);
  }

  async count(): Promise<number> {
    const result = await this.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM research_tasks');
    return result.rows[0]!.n;
  }
}

export interface InsertResearchSourceInput {
  researchTaskId: string;
  documentId: string | null;
  url: string;
  domain: string;
  trustLevel: ResearchSourceRecord['trust_level'];
  rank: number;
  selected: boolean;
  reason: string | null;
}

export class ResearchSourcesRepository implements RepoBase {
  constructor(readonly pool: Pool) {}

  async insert(input: InsertResearchSourceInput): Promise<ResearchSourceRecord> {
    const id = generateId('RSR');
    const result = await this.pool.query(
      `INSERT INTO research_sources
         (id, research_task_id, document_id, url, domain, trust_level, rank, selected, reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id, research_task_id, document_id, url, domain, trust_level, rank, selected, fetch_status, fetched_bytes, fetched_at, reason, created_at`,
      [
        id,
        input.researchTaskId,
        input.documentId,
        input.url,
        input.domain,
        input.trustLevel,
        input.rank,
        input.selected,
        input.reason,
      ],
    );
    return mapResearchSource(result.rows[0]!);
  }

  async markFetched(id: string, status: string, fetchedBytes: number): Promise<void> {
    await this.pool.query(
      'UPDATE research_sources SET fetch_status = $1, fetched_bytes = $2, fetched_at = now() WHERE id = $3',
      [status, fetchedBytes, id],
    );
  }

  async findByResearchTask(researchTaskId: string): Promise<ResearchSourceRecord[]> {
    const result = await this.pool.query(
      `SELECT id, research_task_id, document_id, url, domain, trust_level, rank, selected, fetch_status, fetched_bytes, fetched_at, reason, created_at
       FROM research_sources WHERE research_task_id = $1 ORDER BY rank LIMIT 100`,
      [researchTaskId],
    );
    return result.rows.map(mapResearchSource);
  }
}

// ---------------------------------------------------------------------------
// Row mappers.
// ---------------------------------------------------------------------------

function mapTechnique(row: Record<string, unknown>): SecurityTechniqueRecord {
  return {
    id: row['id'] as string,
    name: row['name'] as string,
    category: row['category'] as SecurityTechniqueRecord['category'],
    description: row['description'] as string,
    preconditions: (row['preconditions'] as string[]) ?? [],
    signals: (row['signals'] as string[]) ?? [],
    test_patterns: (row['test_patterns'] as string[]) ?? [],
    verification_patterns: (row['verification_patterns'] as string[]) ?? [],
    false_positive_conditions: (row['false_positive_conditions'] as string[]) ?? [],
    source_ids: (row['source_ids'] as string[]) ?? [],
    confidence: Number(row['confidence']),
    created_at: requireIso(row['created_at'] as Date),
    updated_at: requireIso(row['updated_at'] as Date),
  };
}

function mapReference(row: Record<string, unknown>): KnowledgeReferenceRecord {
  return {
    id: row['id'] as string,
    document_id: (row['document_id'] as string | null) ?? null,
    chunk_id: (row['chunk_id'] as string | null) ?? null,
    technique_id: (row['technique_id'] as string | null) ?? null,
    hypothesis_id: (row['hypothesis_id'] as string | null) ?? null,
    kind: row['kind'] as KnowledgeReferenceRecord['kind'],
    value: row['value'] as string,
    context: (row['context'] as string | null) ?? null,
    created_at: requireIso(row['created_at'] as Date),
  };
}

function mapQuery(row: Record<string, unknown>): KnowledgeQueryRecord {
  return {
    id: row['id'] as string,
    engagement_id: (row['engagement_id'] as string | null) ?? null,
    hypothesis_id: (row['hypothesis_id'] as string | null) ?? null,
    requested_by: row['requested_by'] as string,
    query: row['query'] as string,
    categories: (row['categories'] as string[]) ?? [],
    technologies: (row['technologies'] as string[]) ?? [],
    mode: row['mode'] as KnowledgeQueryRecord['mode'],
    cache_key: (row['cache_key'] as string | null) ?? null,
    cache_hit: (row['cache_hit'] as boolean) ?? false,
    result_count: row['result_count'] as number,
    tokens_estimate: row['tokens_estimate'] as number,
    created_at: requireIso(row['created_at'] as Date),
  };
}

function mapResult(row: Record<string, unknown>): KnowledgeResultRecord {
  return {
    id: row['id'] as string,
    query_id: row['query_id'] as string,
    rank: row['rank'] as number,
    chunk_id: (row['chunk_id'] as string | null) ?? null,
    technique_id: (row['technique_id'] as string | null) ?? null,
    relevance: Number(row['relevance']),
    keyword_score: Number(row['keyword_score']),
    semantic_score: Number(row['semantic_score']),
    trust_score: Number(row['trust_score']),
    freshness_score: Number(row['freshness_score']),
    final_score: Number(row['final_score']),
    included: (row['included'] as boolean) ?? false,
    created_at: requireIso(row['created_at'] as Date),
  };
}

function mapResearchTask(row: Record<string, unknown>): ResearchTaskRecord {
  return {
    id: row['id'] as string,
    engagement_id: (row['engagement_id'] as string | null) ?? null,
    requested_by: row['requested_by'] as string,
    question: row['question'] as string,
    hypothesis: (row['hypothesis'] as string | null) ?? null,
    required_evidence: (row['required_evidence'] as string[]) ?? [],
    source_constraints: (row['source_constraints'] as string[]) ?? [],
    mode: row['mode'] as ResearchTaskRecord['mode'],
    status: row['status'] as ResearchTaskRecord['status'],
    max_sources: row['max_sources'] as number,
    max_tokens: row['max_tokens'] as number,
    deadline_ms: row['deadline_ms'] as number,
    started_at: row['started_at'] ? requireIso(row['started_at'] as Date) : null,
    completed_at: row['completed_at'] ? requireIso(row['completed_at'] as Date) : null,
    error: (row['error'] as string | null) ?? null,
    result: (row['result'] as Record<string, unknown> | null) ?? null,
    tokens_consumed: row['tokens_consumed'] as number,
    created_at: requireIso(row['created_at'] as Date),
  };
}

function mapResearchSource(row: Record<string, unknown>): ResearchSourceRecord {
  return {
    id: row['id'] as string,
    research_task_id: row['research_task_id'] as string,
    document_id: (row['document_id'] as string | null) ?? null,
    url: row['url'] as string,
    domain: row['domain'] as string,
    trust_level: row['trust_level'] as ResearchSourceRecord['trust_level'],
    rank: row['rank'] as number,
    selected: (row['selected'] as boolean) ?? false,
    fetch_status: (row['fetch_status'] as string | null) ?? null,
    fetched_bytes: row['fetched_bytes'] as number,
    fetched_at: row['fetched_at'] ? requireIso(row['fetched_at'] as Date) : null,
    reason: (row['reason'] as string | null) ?? null,
    created_at: requireIso(row['created_at'] as Date),
  };
}
