-- Part 5 — Knowledge documents with full provenance (spec §7-§8, §25, §94).
-- Version history is preserved: a changed source creates a NEW version row
-- and supersedes the old one; nothing is silently overwritten (§25).
-- Raw bytes live in object storage; DB stores artifact reference + hash.
CREATE TABLE knowledge_documents (
    id text PRIMARY KEY,
    source_id text NOT NULL REFERENCES knowledge_sources (id) ON DELETE CASCADE,
    title text NOT NULL,
    canonical_url text NOT NULL,
    content_hash text NOT NULL,
    document_type text NOT NULL,
    trust_level text NOT NULL,
    version integer NOT NULL DEFAULT 1,
    published_at timestamptz,
    retrieved_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    ingestion_status text NOT NULL DEFAULT 'PENDING',
    ingestion_error text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    artifact_ref text,
    artifact_hash text,
    chunk_count integer NOT NULL DEFAULT 0,
    ctf jsonb,
    is_latest boolean NOT NULL DEFAULT true,
    superseded_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_documents_version_unique UNIQUE (canonical_url, version),
    CONSTRAINT knowledge_documents_type_check CHECK (document_type IN ('HTML','MARKDOWN','TXT','JSON','XML','PDF')),
    CONSTRAINT knowledge_documents_trust_check CHECK (trust_level IN ('OFFICIAL','TRUSTED_TRAINING','RESEARCH','CTF','COMMUNITY','UNTRUSTED')),
    CONSTRAINT knowledge_documents_status_check CHECK (ingestion_status IN ('PENDING','FETCHED','PARSED','INDEXED','EMBEDDING_FAILED','FAILED')),
    CONSTRAINT knowledge_documents_version_positive CHECK (version >= 1),
    CONSTRAINT knowledge_documents_hash_len CHECK (length(content_hash) = 64)
);

-- Duplicate detection across URLs (§67): same content links to a canonical
-- document instead of being re-indexed; provenance is never deleted.
CREATE INDEX idx_knowledge_documents_hash ON knowledge_documents (content_hash);
CREATE INDEX idx_knowledge_documents_source ON knowledge_documents (source_id, is_latest);
CREATE INDEX idx_knowledge_documents_latest ON knowledge_documents (canonical_url) WHERE is_latest;
