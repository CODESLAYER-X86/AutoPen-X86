-- Part 3 — captured downloads (spec §37). Content is UNTRUSTED evidence.
CREATE TABLE downloads (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    page_id text,
    url text NOT NULL,
    filename text NOT NULL,
    content_type text,
    size integer NOT NULL DEFAULT 0,
    sha256 text NOT NULL,
    evidence_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_downloads_engagement ON downloads (engagement_id, created_at DESC);
