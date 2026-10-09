-- Part 5 — Query cache packet storage (spec §65).
-- The compact packet produced for a cache hit is stored as JSON so the
-- cache serves identical requests without re-ranking; entries expire via
-- the TTL checked in application code (cache_key + created_at).
CREATE TABLE knowledge_cache (
    cache_key text PRIMARY KEY,
    query_id text NOT NULL REFERENCES knowledge_queries (id) ON DELETE CASCADE,
    packet jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX idx_knowledge_cache_expiry ON knowledge_cache (expires_at);
