-- Part 6 §65-§66: reasoning branches group hypotheses that share an
-- interpretation of the evidence. Pruned branches are PRESERVED — never
-- deleted (§66 "preserve branch history").
CREATE TABLE reasoning_branches (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    parent_branch_id text REFERENCES reasoning_branches (id) ON DELETE SET NULL,
    -- Branch origin: signal, CTF clue, hypothesis candidate or manual.
    origin text NOT NULL DEFAULT 'SIGNAL',
    origin_ref text,
    focus text NOT NULL DEFAULT '',
    hypothesis_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    score double precision NOT NULL DEFAULT 0.5,
    status text NOT NULL DEFAULT 'ACTIVE',
    pruned_reason text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT branch_status_check CHECK (
        status IN ('ACTIVE', 'PAUSED', 'PRUNED', 'DISPROVED', 'COMPLETED')
    ),
    CONSTRAINT branch_score_range CHECK (score >= 0 AND score <= 1)
);

CREATE INDEX idx_branches_engagement ON reasoning_branches (engagement_id, status, score DESC);
CREATE INDEX idx_branches_parent ON reasoning_branches (parent_branch_id);
