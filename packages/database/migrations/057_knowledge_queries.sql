-- Part 5 — Knowledge query audit + cache (spec §65, §85, §86).
-- Every retrieval is recorded: who requested it, for which engagement/
-- hypothesis, the query, the result count and token estimate. The cache
-- key covers query + taxonomy + technology + index version (§65).
CREATE TABLE knowledge_queries (
    id text PRIMARY KEY,
    engagement_id text,
    hypothesis_id text,
    requested_by text NOT NULL,
    query text NOT NULL,
    categories jsonb NOT NULL DEFAULT '[]'::jsonb,
    technologies jsonb NOT NULL DEFAULT '[]'::jsonb,
    mode text NOT NULL DEFAULT 'LOCAL_ONLY',
    cache_key text,
    cache_hit boolean NOT NULL DEFAULT false,
    result_count integer NOT NULL DEFAULT 0,
    tokens_estimate integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_queries_mode_check CHECK (mode IN ('LOCAL_ONLY','CURATED_WEB','OPEN_RESEARCH','CTF_RESEARCH'))
);

CREATE INDEX idx_knowledge_queries_cache ON knowledge_queries (cache_key, created_at DESC);
CREATE INDEX idx_knowledge_queries_engagement ON knowledge_queries (engagement_id, created_at DESC);
