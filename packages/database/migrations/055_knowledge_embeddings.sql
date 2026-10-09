-- Part 5 — Embedding storage with lifecycle metadata (spec §14, §95).
-- Embedding model + version + dimension are stored per row: changing the
-- embedding model triggers a reindex, never a silent vector mix (§95).
-- Vectors are real[] arrays; cosine similarity is computed by the vector
-- index implementation over bounded candidate sets.
CREATE TABLE knowledge_chunk_embeddings (
    chunk_id text PRIMARY KEY REFERENCES knowledge_chunks (id) ON DELETE CASCADE,
    embedding double precision[] NOT NULL,
    embedding_model text NOT NULL,
    embedding_version integer NOT NULL DEFAULT 1,
    dimension integer NOT NULL,
    content_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_embeddings_dimension_positive CHECK (dimension > 0),
    CONSTRAINT knowledge_embeddings_model_len CHECK (length(embedding_model) >= 1)
);

CREATE INDEX idx_knowledge_embeddings_model ON knowledge_chunk_embeddings (embedding_model, embedding_version);
