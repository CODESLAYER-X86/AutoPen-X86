/**
 * Security Knowledge & Web Research System contracts (spec Part 5).
 *
 * Canonical shapes for the knowledge subsystem: source registry, documents
 * with provenance, semantic chunks, structured security techniques, research
 * tasks and the compact knowledge packet delivered to agents.
 *
 * Central principle (spec Part 5 §135):
 *
 *   KNOWLEDGE != EVIDENCE  and  KNOWLEDGE != AUTHORITY
 *
 * Knowledge can recommend a testing strategy; it can never constitute target
 * evidence, modify scope, or override policy.
 */
import { z } from 'zod';
import {
  CTF_RETRIEVAL_MODES,
  KNOWLEDGE_CHUNK_KINDS,
  KNOWLEDGE_DOCUMENT_TYPES,
  KNOWLEDGE_INGESTION_STATUSES,
  KNOWLEDGE_REFERENCE_KINDS,
  KNOWLEDGE_SOURCE_TYPES,
  KNOWLEDGE_TRUST_LEVELS,
  KNOWLEDGE_UPDATE_STRATEGIES,
  RESEARCH_MODES,
  RESEARCH_STATUSES,
  SECURITY_TAXONOMY,
} from '@aegis/shared';
import { IdSchema, IsoDateTimeSchema } from './common.js';

// ---------------------------------------------------------------------------
// Source registry (spec §5-§6, §3-§4).
// ---------------------------------------------------------------------------

export const KnowledgeCrawlPolicySchema = z.object({
  /** Curated sync allowlist (spec §80). */
  allowed_domains: z.array(z.string().max(253)).max(64).default([]),
  blocked_domains: z.array(z.string().max(253)).max(256).default([]),
  /** Explicit URL paths to sync; a curated source needs no crawling (§28). */
  entry_paths: z.array(z.string().max(2048)).max(500).default([]),
  /** Aggressive crawling is forbidden (§81): only official APIs/feeds. */
  respect_robots: z.boolean().default(true),
});
export type KnowledgeCrawlPolicy = z.infer<typeof KnowledgeCrawlPolicySchema>;

export const KnowledgeSourceRecordSchema = z.object({
  id: IdSchema,
  name: z.string().min(1).max(200),
  type: z.enum(KNOWLEDGE_SOURCE_TYPES),
  base_url: z.string().max(2048),
  trust_level: z.enum(KNOWLEDGE_TRUST_LEVELS),
  enabled: z.boolean(),
  update_strategy: z.enum(KNOWLEDGE_UPDATE_STRATEGIES),
  crawl_policy: KnowledgeCrawlPolicySchema,
  license_notes: z.string().max(2000).nullable(),
  last_synced: IsoDateTimeSchema.nullable(),
  configuration: z.record(z.string(), z.unknown()),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type KnowledgeSourceRecord = z.infer<typeof KnowledgeSourceRecordSchema>;

// ---------------------------------------------------------------------------
// Documents + provenance (spec §7-§8, §25).
// ---------------------------------------------------------------------------

export const KnowledgeDocumentMetadataSchema = z.object({
  author: z.string().max(256).nullable().default(null),
  language: z.string().max(16).nullable().default(null),
  /** Deterministic metadata extraction (§57). */
  technologies: z.array(z.string().max(64)).max(32).default([]),
  cve_refs: z.array(z.string().max(32)).max(64).default([]),
  cwe_refs: z.array(z.string().max(32)).max(64).default([]),
  owasp_refs: z.array(z.string().max(64)).max(64).default([]),
  http_methods: z.array(z.string().max(16)).max(16).default([]),
  protocols: z.array(z.string().max(32)).max(16).default([]),
  security_categories: z.array(z.enum(SECURITY_TAXONOMY)).max(32).default([]),
});
export type KnowledgeDocumentMetadata = z.infer<typeof KnowledgeDocumentMetadataSchema>;

export const KnowledgeDocumentRecordSchema = z.object({
  id: IdSchema,
  source_id: IdSchema,
  title: z.string().max(500),
  canonical_url: z.string().max(2048),
  /** sha256 of the parsed content — dedup/versioning key (§25, §67). */
  content_hash: z.string().length(64),
  document_type: z.enum(KNOWLEDGE_DOCUMENT_TYPES),
  trust_level: z.enum(KNOWLEDGE_TRUST_LEVELS),
  /** Version counter per canonical URL — history preserved (§25). */
  version: z.number().int().min(1),
  published_at: IsoDateTimeSchema.nullable(),
  retrieved_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
  ingestion_status: z.enum(KNOWLEDGE_INGESTION_STATUSES),
  ingestion_error: z.string().max(2000).nullable(),
  metadata: KnowledgeDocumentMetadataSchema,
  /** Raw artifact: object-store reference + hash (§94), never inline bytes. */
  artifact_ref: z.string().max(512).nullable(),
  artifact_hash: z.string().length(64).nullable(),
  chunk_count: z.number().int().min(0),
  /** CTF write-up structured fields (§39); null for non-CTF documents. */
  ctf: z
    .object({
      challenge_name: z.string().max(256),
      event: z.string().max(128).nullable(),
      year: z.number().int().min(1990).max(2100).nullable(),
      category: z.string().max(64).nullable(),
      platform: z.string().max(128).nullable(),
      difficulty: z.string().max(64).nullable(),
      description: z.string().max(4000),
      technique: z.string().max(1000).nullable(),
      solution_summary: z.string().max(4000).nullable(),
    })
    .nullable()
    .default(null),
  is_latest: z.boolean(),
  superseded_by: IdSchema.nullable(),
});
export type KnowledgeDocumentRecord = z.infer<typeof KnowledgeDocumentRecordSchema>;

export const KnowledgeChunkRecordSchema = z.object({
  id: IdSchema,
  document_id: IdSchema,
  /** Full heading path — parent-child retrieval context (§12). */
  heading: z.string().max(500).nullable(),
  heading_path: z.array(z.string().max(256)).max(12).default([]),
  section: z.string().max(256).nullable(),
  content: z.string().max(32_768),
  token_estimate: z.number().int().min(0),
  kind: z.enum(KNOWLEDGE_CHUNK_KINDS),
  /** Code language for CODE chunks (§56). */
  code_language: z.string().max(32).nullable(),
  content_hash: z.string().length(64),
  parent_chunk_id: IdSchema.nullable(),
  created_at: IsoDateTimeSchema,
});
export type KnowledgeChunkRecord = z.infer<typeof KnowledgeChunkRecordSchema>;

// ---------------------------------------------------------------------------
// Security techniques (spec §42-§43, §46) and references (§57, §76, §59).
// ---------------------------------------------------------------------------

export const SecurityTechniqueRecordSchema = z.object({
  id: IdSchema,
  name: z.string().min(1).max(256),
  category: z.enum(SECURITY_TAXONOMY),
  description: z.string().max(4000),
  preconditions: z.array(z.string().max(500)).max(16),
  signals: z.array(z.string().max(500)).max(16),
  test_patterns: z.array(z.string().max(500)).max(16),
  verification_patterns: z.array(z.string().max(500)).max(16),
  false_positive_conditions: z.array(z.string().max(500)).max(16),
  source_ids: z.array(IdSchema).max(32),
  confidence: z.number().min(0).max(1),
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type SecurityTechniqueRecord = z.infer<typeof SecurityTechniqueRecordSchema>;

export const KnowledgeReferenceRecordSchema = z.object({
  id: IdSchema,
  document_id: IdSchema.nullable(),
  chunk_id: IdSchema.nullable(),
  technique_id: IdSchema.nullable(),
  /** Engagement hypothesis cross-link (§59). */
  hypothesis_id: IdSchema.nullable(),
  kind: z.enum(KNOWLEDGE_REFERENCE_KINDS),
  value: z.string().max(128),
  context: z.string().max(500).nullable(),
  created_at: IsoDateTimeSchema,
});
export type KnowledgeReferenceRecord = z.infer<typeof KnowledgeReferenceRecordSchema>;

// ---------------------------------------------------------------------------
// Retrieval request (spec §17-§19) and hybrid scoring (§68-§69).
// ---------------------------------------------------------------------------

export const KnowledgeSearchRequestSchema = z.object({
  query: z.string().min(1).max(1000),
  engagement_id: IdSchema.nullable().default(null),
  hypothesis_id: IdSchema.nullable().default(null),
  /** Taxonomy filter — context-aware retrieval (§18). */
  categories: z.array(z.enum(SECURITY_TAXONOMY)).max(8).default([]),
  technologies: z.array(z.string().max(64)).max(12).default([]),
  mode: z.enum(RESEARCH_MODES).default('LOCAL_ONLY'),
  max_results: z.number().int().min(1).max(24).default(8),
  /** Explicit token budget for the packet (§62, §63). */
  max_tokens: z.number().int().min(200).max(20_000).default(2500),
  retrieval_mode: z.enum(CTF_RETRIEVAL_MODES).optional(),
});
export type KnowledgeSearchRequest = z.infer<typeof KnowledgeSearchRequestSchema>;

export const RetrievedChunkSchema = z.object({
  chunk_id: IdSchema,
  document_id: IdSchema,
  source_name: z.string().max(200),
  source_id: IdSchema,
  title: z.string().max(500),
  url: z.string().max(2048),
  section: z.string().max(256).nullable(),
  heading: z.string().max(500).nullable(),
  kind: z.enum(KNOWLEDGE_CHUNK_KINDS),
  trust_level: z.enum(KNOWLEDGE_TRUST_LEVELS),
  trust_score: z.number().min(0).max(1),
  freshness_score: z.number().min(0).max(1),
  keyword_score: z.number().min(0).max(1),
  semantic_score: z.number().min(0).max(1),
  relevance: z.number().min(0).max(1),
  content: z.string().max(8192),
  token_estimate: z.number().int().min(0),
  published_at: IsoDateTimeSchema.nullable(),
  retrieved_at: IsoDateTimeSchema,
  /** Multiple sources corroborate this content (§73). */
  corroborated: z.boolean().default(false),
});
export type RetrievedChunk = z.infer<typeof RetrievedChunkSchema>;

export const RetrievedTechniqueSchema = z.object({
  technique_id: IdSchema,
  name: z.string().max(256),
  category: z.enum(SECURITY_TAXONOMY),
  description: z.string().max(2000),
  preconditions: z.array(z.string().max(500)).max(8),
  signals: z.array(z.string().max(500)).max(8),
  test_patterns: z.array(z.string().max(500)).max(8),
  verification_patterns: z.array(z.string().max(500)).max(8),
  false_positive_conditions: z.array(z.string().max(500)).max(8),
  confidence: z.number().min(0).max(1),
  /** Knowledge-to-test translation (§46): why this technique matched. */
  relevant_because: z.string().max(1000),
  suggested_evidence: z.array(z.string().max(500)).max(8),
  alternative_explanations: z.array(z.string().max(500)).max(8),
});
export type RetrievedTechnique = z.infer<typeof RetrievedTechniqueSchema>;

/** Compact model-facing packet (spec §61, §87-§88). */
export const KnowledgePacketSchema = z.object({
  query_id: IdSchema,
  query: z.string().max(1000),
  cache_hit: z.boolean(),
  mode: z.enum(RESEARCH_MODES),
  results: z.array(RetrievedChunkSchema).max(24),
  techniques: z.array(RetrievedTechniqueSchema).max(8),
  total_available: z.number().int().min(0),
  packet_tokens: z.number().int().min(0),
  truncated: z.boolean(),
  notes: z.array(z.string().max(500)).max(16),
  /** Preserved source disagreement (§73, §111) — never silently averaged. */
  disagreements: z
    .array(
      z.object({
        topic: z.string().max(300),
        position_a: z.string().max(300),
        position_b: z.string().max(300),
      }),
    )
    .max(8)
    .default([]),
});
export type KnowledgePacket = z.infer<typeof KnowledgePacketSchema>;

// ---------------------------------------------------------------------------
// Similar cases / case memory (spec §36-§40, §102).
// ---------------------------------------------------------------------------

export const SimilarCaseRequestSchema = z.object({
  engagement_id: IdSchema.nullable().default(null),
  observation: z.string().min(1).max(2000),
  hypothesis_category: z.enum(SECURITY_TAXONOMY).nullable().default(null),
  technology: z.string().max(64).nullable().default(null),
  workflow_description: z.string().max(2000).nullable().default(null),
  retrieval_mode: z.enum(CTF_RETRIEVAL_MODES).default('PATTERN_RETRIEVAL'),
  max_results: z.number().int().min(1).max(12).default(5),
});
export type SimilarCaseRequest = z.infer<typeof SimilarCaseRequestSchema>;

export const SimilarCaseSchema = z.object({
  document_id: IdSchema,
  title: z.string().max(500),
  url: z.string().max(2048),
  source_name: z.string().max(200),
  trust_level: z.enum(KNOWLEDGE_TRUST_LEVELS),
  year: z.number().int().nullable(),
  event: z.string().max(128).nullable(),
  category: z.string().max(64).nullable(),
  difficulty: z.string().max(64).nullable(),
  description_excerpt: z.string().max(1500),
  technique: z.string().max(1000).nullable(),
  solution_summary: z.string().max(1500).nullable(),
  relevance: z.number().min(0).max(1),
});
export type SimilarCase = z.infer<typeof SimilarCaseSchema>;

export const SimilarCaseResultSchema = z.object({
  cases: z.array(SimilarCaseSchema).max(12),
  retrieval_mode: z.enum(CTF_RETRIEVAL_MODES),
  notes: z.array(z.string().max(500)).max(8),
});
export type SimilarCaseResult = z.infer<typeof SimilarCaseResultSchema>;

// ---------------------------------------------------------------------------
// Live research (spec §30-§31, §71-§73, §83).
// ---------------------------------------------------------------------------

export const ResearchRequestSchema = z.object({
  question: z.string().min(1).max(2000),
  engagement_id: IdSchema.nullable().default(null),
  hypothesis: z.string().max(2000).nullable().default(null),
  required_evidence: z.array(z.string().max(500)).max(8).default([]),
  source_constraints: z.array(z.string().max(253)).max(16).default([]),
  mode: z.enum(RESEARCH_MODES).default('CURATED_WEB'),
  max_sources: z.number().int().min(1).max(10).default(5),
  max_tokens: z.number().int().min(200).max(20_000).default(4000),
});
export type ResearchRequest = z.infer<typeof ResearchRequestSchema>;

export const ResearchEvidenceSchema = z.object({
  document_id: IdSchema.nullable(),
  url: z.string().max(2048),
  source_name: z.string().max(200),
  trust_level: z.enum(KNOWLEDGE_TRUST_LEVELS),
  excerpt: z.string().max(2000),
  relevance: z.number().min(0).max(1),
});
export type ResearchEvidence = z.infer<typeof ResearchEvidenceSchema>;

export const ResearchResultSchema = z.object({
  research_id: IdSchema,
  question: z.string().max(2000),
  status: z.enum(RESEARCH_STATUSES),
  mode: z.enum(RESEARCH_MODES),
  summary: z.string().max(3000),
  evidence: z.array(ResearchEvidenceSchema).max(10),
  /** Corroboration + preserved disagreement (§73, §111). */
  corroboration: z
    .array(
      z.object({
        claim: z.string().max(500),
        source_count: z.number().int().min(2),
      }),
    )
    .max(8),
  disagreements: z
    .array(
      z.object({
        topic: z.string().max(300),
        position_a: z.string().max(300),
        position_b: z.string().max(300),
      }),
    )
    .max(8),
  sources_considered: z.number().int().min(0),
  sources_fetched: z.number().int().min(0),
  tokens_estimate: z.number().int().min(0),
  notes: z.array(z.string().max(500)).max(16),
});
export type ResearchResult = z.infer<typeof ResearchResultSchema>;

export const ResearchTaskRecordSchema = z.object({
  id: IdSchema,
  engagement_id: IdSchema.nullable(),
  requested_by: z.string().max(128),
  question: z.string().max(2000),
  hypothesis: z.string().max(2000).nullable(),
  required_evidence: z.array(z.string().max(500)).max(8),
  source_constraints: z.array(z.string().max(253)).max(16),
  mode: z.enum(RESEARCH_MODES),
  status: z.enum(RESEARCH_STATUSES),
  max_sources: z.number().int().min(1).max(10),
  max_tokens: z.number().int().min(200).max(20_000),
  deadline_ms: z.number().int().min(1000),
  started_at: IsoDateTimeSchema.nullable(),
  completed_at: IsoDateTimeSchema.nullable(),
  error: z.string().max(2000).nullable(),
  result: ResearchResultSchema.nullable(),
  tokens_consumed: z.number().int().min(0),
  created_at: IsoDateTimeSchema,
});
export type ResearchTaskRecord = z.infer<typeof ResearchTaskRecordSchema>;

// ---------------------------------------------------------------------------
// Fetch (spec §26-§27, §34) and ingestion (§115).
// ---------------------------------------------------------------------------

export const KnowledgeFetchRequestSchema = z.object({
  url: z.string().min(1).max(2048),
  source_id: IdSchema.nullable().default(null),
  engagement_id: IdSchema.nullable().default(null),
  /** Optional pre-known document type; auto-detected otherwise. */
  document_type: z.enum(KNOWLEDGE_DOCUMENT_TYPES).optional(),
  title_override: z.string().max(500).optional(),
  /** CTF write-up structured fields when ingesting a write-up (§39). */
  ctf: z
    .object({
      challenge_name: z.string().max(256),
      event: z.string().max(128).nullable().default(null),
      year: z.number().int().min(1990).max(2100).nullable().default(null),
      category: z.string().max(64).nullable().default(null),
      platform: z.string().max(128).nullable().default(null),
      difficulty: z.string().max(64).nullable().default(null),
      description: z.string().max(4000),
      technique: z.string().max(1000).nullable().default(null),
      solution_summary: z.string().max(4000).nullable().default(null),
    })
    .optional(),
});
export type KnowledgeFetchRequest = z.infer<typeof KnowledgeFetchRequestSchema>;

export const IngestionOutcomeSchema = z.object({
  document_id: IdSchema,
  canonical_url: z.string().max(2048),
  content_hash: z.string().length(64),
  version: z.number().int().min(1),
  new_version: z.boolean(),
  /** Same content already ingested under another URL (§67). */
  duplicate_of: IdSchema.nullable(),
  document_type: z.enum(KNOWLEDGE_DOCUMENT_TYPES),
  chunks_created: z.number().int().min(0),
  embeddings_created: z.number().int().min(0),
  embedding_model: z.string().max(128).nullable(),
  ingestion_status: z.enum(KNOWLEDGE_INGESTION_STATUSES),
  references_extracted: z.number().int().min(0),
  techniques_extracted: z.number().int().min(0),
  error: z.string().max(2000).nullable(),
});
export type IngestionOutcome = z.infer<typeof IngestionOutcomeSchema>;

// ---------------------------------------------------------------------------
// Worker tool inputs (spec §33-§36).
// ---------------------------------------------------------------------------

export const KnowledgeSearchToolInputSchema = z.object({
  engagement_id: IdSchema.optional(),
  query: z.string().min(1).max(1000),
  categories: z.array(z.enum(SECURITY_TAXONOMY)).max(8).default([]),
  technologies: z.array(z.string().max(64)).max(12).default([]),
  max_results: z.number().int().min(1).max(12).default(6),
  max_tokens: z.number().int().min(200).max(6000).default(1200),
});

export const KnowledgeFetchToolInputSchema = z.object({
  engagement_id: IdSchema.optional(),
  url: z.string().min(1).max(2048),
  document_type: z.enum(KNOWLEDGE_DOCUMENT_TYPES).optional(),
});

export const KnowledgeSearchWebToolInputSchema = z.object({
  engagement_id: IdSchema.optional(),
  query: z.string().min(1).max(500),
  max_results: z.number().int().min(1).max(10).default(5),
  domain_allowlist: z.array(z.string().max(253)).max(16).default([]),
  domain_denylist: z.array(z.string().max(253)).max(32).default([]),
});

export const KnowledgeSimilarCasesToolInputSchema = z.object({
  engagement_id: IdSchema.optional(),
  observation: z.string().min(1).max(2000),
  hypothesis_category: z.enum(SECURITY_TAXONOMY).nullable().default(null),
  technology: z.string().max(64).nullable().default(null),
  max_results: z.number().int().min(1).max(8).default(3),
});

// ---------------------------------------------------------------------------
// Agent knowledge-context seam (spec §87, Part 5 §120).
// ---------------------------------------------------------------------------

/**
 * Compact knowledge context provider for the strategic leader. Everything
 * this returns is advisory content: retrieved chunks are UNTRUSTED external
 * knowledge and MUST be rendered inside explicit delimiters by the prompt
 * layer (§41, §50); metadata (source, trust, relevance) is trusted.
 */
export interface KnowledgeContextProvider {
  buildKnowledgeContext(
    engagementId: string,
    options?: { maxTokens?: number },
  ): Promise<{
    /** Trusted: source names, trust levels, relevance — no page content. */
    trusted_summary: Record<string, unknown>;
    /** Untrusted: retrieved excerpts, wrapped in delimiters upstream. */
    untrusted_detail: Record<string, unknown> | null;
  }>;
}
