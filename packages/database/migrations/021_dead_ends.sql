-- Dead-end memory (spec Part 2 §27): recorded so the leader sees previously
-- exhausted investigation branches before proposing them again.
CREATE TABLE dead_ends (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    description text NOT NULL,
    tests jsonb NOT NULL DEFAULT '[]'::jsonb,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_dead_ends_engagement ON dead_ends (engagement_id, created_at DESC);
CREATE INDEX idx_dead_ends_hypothesis ON dead_ends (hypothesis_id);
