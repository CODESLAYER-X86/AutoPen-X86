-- Part 3 — browser context registry (spec §3-§6, §30).
-- One row per isolated Playwright context; status tracks the §5 lifecycle.
CREATE TABLE browser_contexts (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    identity_id text,
    status text NOT NULL,
    security_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    CONSTRAINT browser_contexts_status_check CHECK (
        status IN ('CREATE','INITIALIZE','READY','ACTIVE','PAUSED','EXPIRED','CLOSING','CLOSED','FAILED')
    )
);

CREATE INDEX idx_browser_contexts_engagement ON browser_contexts (engagement_id, created_at DESC);
CREATE INDEX idx_browser_contexts_identity ON browser_contexts (identity_id);
