-- Part 5 — Persisted retrieval results (spec §85, §97-§98).
-- Each scored candidate of a query is retained with its separate scoring
-- dimensions (relevance / trust / freshness are NEVER collapsed, §68) so
-- retrieval quality can be evaluated after the fact (Recall@K, MRR, NDCG).
CREATE TABLE knowledge_results (
    id text PRIMARY KEY,
    query_id text NOT NULL REFERENCES knowledge_queries (id) ON DELETE CASCADE,
    rank integer NOT NULL,
    chunk_id text REFERENCES knowledge_chunks (id) ON DELETE SET NULL,
    technique_id text REFERENCES security_techniques (id) ON DELETE SET NULL,
    relevance numeric NOT NULL,
    keyword_score numeric NOT NULL DEFAULT 0,
    semantic_score numeric NOT NULL DEFAULT 0,
    trust_score numeric NOT NULL DEFAULT 0,
    freshness_score numeric NOT NULL DEFAULT 0,
    final_score numeric NOT NULL DEFAULT 0,
    included boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_results_rank_nonneg CHECK (rank >= 0),
    CONSTRAINT knowledge_results_score_range CHECK (
        relevance >= 0 AND relevance <= 1
        AND keyword_score >= 0 AND keyword_score <= 1
        AND semantic_score >= 0 AND semantic_score <= 1
        AND trust_score >= 0 AND trust_score <= 1
        AND freshness_score >= 0 AND freshness_score <= 1
    )
);

CREATE INDEX idx_knowledge_results_query ON knowledge_results (query_id, rank);
CREATE INDEX idx_knowledge_results_chunk ON knowledge_results (chunk_id);
