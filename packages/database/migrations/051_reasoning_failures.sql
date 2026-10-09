-- Part 4 — Reasoning processor failure log (spec §112).
-- If an extractor crashes, the engagement must NOT crash: the failure is
-- recorded with the event id and error, and other processing continues.
-- Raw events remain durable even when an extractor fails (§110).
CREATE TABLE reasoning_failures (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    processor text NOT NULL,
    event_id text,
    event_type text,
    error jsonb NOT NULL DEFAULT '{}'::jsonb,
    retry_count integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'NEW',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT reasoning_failures_status_check CHECK (status IN ('NEW','RESOLVED','SKIPPED'))
);

CREATE INDEX idx_reasoning_failures_engagement ON reasoning_failures (engagement_id, created_at DESC);
