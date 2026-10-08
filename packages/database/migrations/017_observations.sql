-- Observations (spec Part 2 §2, §16): structured worker-derived facts that
-- feed hypothesis updates and the strategic context.
-- NOTE: the task_id foreign key is added in migration 018 (tasks table).
CREATE TABLE observations (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    type text NOT NULL,
    description text NOT NULL,
    confidence double precision NOT NULL DEFAULT 0.5,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT observations_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX idx_observations_engagement ON observations (engagement_id, created_at DESC);
CREATE INDEX idx_observations_task ON observations (task_id);
CREATE INDEX idx_observations_hypothesis ON observations (hypothesis_id);
