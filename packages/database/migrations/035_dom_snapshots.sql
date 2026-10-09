-- Part 3 — normalized DOM snapshots (spec §31-§33).
CREATE TABLE dom_snapshots (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    page_id text NOT NULL,
    url text NOT NULL,
    title text,
    snapshot jsonb NOT NULL,
    evidence_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_dom_snapshots_engagement ON dom_snapshots (engagement_id, created_at DESC);
CREATE INDEX idx_dom_snapshots_context ON dom_snapshots (context_id);
