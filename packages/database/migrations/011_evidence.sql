-- Evidence (spec §22): immutable, content-addressed by SHA-256.
-- Binary/blob content lives in object storage; `content_reference` is the
-- opaque pointer. Derived evidence references its parent.
CREATE TABLE evidence (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    type text NOT NULL,
    source text NOT NULL,
    content_reference text NOT NULL,
    sha256 char(64) NOT NULL,
    parent_id text REFERENCES evidence (id),
    task_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Idempotency: identical content within an engagement maps to one record.
CREATE UNIQUE INDEX idx_evidence_dedupe ON evidence (engagement_id, sha256);
CREATE INDEX idx_evidence_engagement ON evidence (engagement_id, created_at DESC);
