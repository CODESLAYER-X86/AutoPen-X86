-- Part 3 — structured browser event stream (spec §10-§11).
-- Payloads are bounded JSON; values are redacted upstream.
CREATE TABLE browser_events (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    page_id text,
    event_type text NOT NULL,
    url text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL
);

CREATE INDEX idx_browser_events_engagement ON browser_events (engagement_id, occurred_at DESC);
CREATE INDEX idx_browser_events_context ON browser_events (context_id, occurred_at DESC);
