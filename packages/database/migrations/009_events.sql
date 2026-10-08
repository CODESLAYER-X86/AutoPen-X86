-- Internal event log (spec §14). Every significant operation is traceable
-- to engagement / task / trace / actor via correlation columns.
CREATE TABLE events (
    id text PRIMARY KEY,
    type text NOT NULL,
    engagement_id text REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text,
    trace_id text,
    actor_id text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_engagement ON events (engagement_id, occurred_at DESC);
CREATE INDEX idx_events_type ON events (type, occurred_at DESC);
