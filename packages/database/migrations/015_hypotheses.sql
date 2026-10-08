-- Hypotheses (spec Part 2 §22-§23). Persistent hypothesis registry with
-- branching (parent_hypothesis_id, §53) and competing hypotheses (§26).
CREATE TABLE hypotheses (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    type text NOT NULL DEFAULT 'UNKNOWN',
    statement text NOT NULL,
    status text NOT NULL DEFAULT 'PROPOSED',
    confidence double precision NOT NULL DEFAULT 0.5,
    priority double precision NOT NULL DEFAULT 0.5,
    source text NOT NULL DEFAULT 'leader',
    parent_hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    confirmed_at timestamptz,
    disproved_at timestamptz,
    CONSTRAINT hypotheses_status_check CHECK (
        status IN ('PROPOSED', 'ACTIVE', 'TESTING', 'SUPPORTED', 'CONFIRMED', 'DISPROVED', 'ABANDONED')
    ),
    CONSTRAINT hypotheses_source_check CHECK (
        source IN ('leader', 'worker', 'human', 'system')
    ),
    CONSTRAINT hypotheses_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT hypotheses_priority_range CHECK (priority >= 0 AND priority <= 1)
);

CREATE INDEX idx_hypotheses_engagement ON hypotheses (engagement_id, status, priority DESC);
CREATE INDEX idx_hypotheses_parent ON hypotheses (parent_hypothesis_id);
