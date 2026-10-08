-- Strategy memory (spec Part 2 §49): versioned high-level strategy changes
-- so the UI can explain why the agent changed direction.
CREATE TABLE strategies (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    run_id text REFERENCES agent_runs (id) ON DELETE CASCADE,
    version integer NOT NULL,
    summary text NOT NULL,
    focus text NOT NULL,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT strategies_version_unique UNIQUE (engagement_id, version)
);

CREATE INDEX idx_strategies_engagement ON strategies (engagement_id, version DESC);
