-- Part 4 — Verification records (spec §72-§74).
-- The verifier is skeptical: checklists evaluate alternative explanations
-- before a hypothesis can be confirmed. Findings are NEVER created directly
-- from an anomaly (§71).
CREATE TABLE verifications (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    kind text NOT NULL,
    alternatives jsonb NOT NULL DEFAULT '[]'::jsonb,
    checklist jsonb NOT NULL DEFAULT '[]'::jsonb,
    status text NOT NULL DEFAULT 'PENDING',
    result jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT verifications_status_check CHECK (status IN ('PENDING','RUNNING','VERIFIED','REFUTED','INCONCLUSIVE'))
);

CREATE INDEX idx_verifications_engagement ON verifications (engagement_id, created_at DESC);
CREATE INDEX idx_verifications_hypothesis ON verifications (hypothesis_id);
