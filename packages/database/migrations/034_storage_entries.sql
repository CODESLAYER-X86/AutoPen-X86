-- Part 3 — localStorage/sessionStorage entries (spec §24).
-- Sensitive values redacted + secret-store referenced.
CREATE TABLE storage_entries (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    identity_id text,
    origin text NOT NULL,
    area text NOT NULL,
    key text NOT NULL,
    value_redacted text NOT NULL,
    is_sensitive boolean NOT NULL DEFAULT false,
    secret_reference text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT storage_entries_area_check CHECK (area IN ('LOCAL','SESSION'))
);

CREATE INDEX idx_storage_entries_context ON storage_entries (context_id);
CREATE INDEX idx_storage_entries_engagement ON storage_entries (engagement_id);
