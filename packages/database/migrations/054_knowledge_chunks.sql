-- Part 5 — Semantic chunks (spec §9-§12, §56).
-- Chunks follow heading boundaries (§10) and keep a heading path so a
-- retrieved excerpt can pull parent context (§12). Code blocks are stored
-- as separate CODE chunks (§56). Keyword search uses PostgreSQL full-text
-- search over heading + content (§13).
CREATE TABLE knowledge_chunks (
    id text PRIMARY KEY,
    document_id text NOT NULL REFERENCES knowledge_documents (id) ON DELETE CASCADE,
    heading text,
    heading_path jsonb NOT NULL DEFAULT '[]'::jsonb,
    section text,
    content text NOT NULL,
    token_estimate integer NOT NULL DEFAULT 0,
    kind text NOT NULL DEFAULT 'TEXT',
    code_language text,
    content_hash text NOT NULL,
    parent_chunk_id text REFERENCES knowledge_chunks (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_chunks_kind_check CHECK (kind IN ('TEXT','HEADING','CODE','TABLE','PROCEDURE','EXAMPLE')),
    CONSTRAINT knowledge_chunks_hash_len CHECK (length(content_hash) = 64),
    CONSTRAINT knowledge_chunks_token_nonneg CHECK (token_estimate >= 0)
);

-- Full-text index: keyword retrieval path (§13). english dictionary.
CREATE INDEX idx_knowledge_chunks_fts ON knowledge_chunks USING gin (to_tsvector('english', coalesce(heading, '') || ' ' || content));
CREATE INDEX idx_knowledge_chunks_document ON knowledge_chunks (document_id);
CREATE INDEX idx_knowledge_chunks_hash ON knowledge_chunks (content_hash);
