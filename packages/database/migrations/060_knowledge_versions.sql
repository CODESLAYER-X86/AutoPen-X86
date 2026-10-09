-- Part 5 — Knowledge index/embedding version markers (spec §65, §95, §117).
-- A row records the active index generation: embedding model + version +
-- chunker parameters. Query cache keys include this version so cached
-- packets are never served across incompatible index generations, and
-- embedding-model changes trigger explicit reindexing rather than silent
-- vector mixing.
CREATE TABLE knowledge_versions (
    id text PRIMARY KEY,
    embedding_model text NOT NULL,
    embedding_version integer NOT NULL,
    chunker_min_tokens integer NOT NULL,
    chunker_max_tokens integer NOT NULL,
    dimension integer NOT NULL,
    active boolean NOT NULL DEFAULT false,
    note text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_knowledge_versions_active ON knowledge_versions (active) WHERE active;
