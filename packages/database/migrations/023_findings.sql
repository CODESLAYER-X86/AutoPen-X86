-- Findings (spec Part 2 §55): a hypothesis must never automatically become a
-- finding. Promotion: HYPOTHESIS -> TESTING -> SUPPORTED -> VERIFICATION ->
-- CONFIRMED FINDING. Verified findings are reportable; rejected ones recorded.
CREATE TABLE findings (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    title text NOT NULL,
    description text NOT NULL,
    severity text NOT NULL DEFAULT 'MEDIUM',
    status text NOT NULL DEFAULT 'PROPOSED',
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT findings_status_check CHECK (status IN ('PROPOSED', 'CONFIRMED', 'REJECTED')),
    CONSTRAINT findings_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX idx_findings_engagement ON findings (engagement_id, status, created_at DESC);
CREATE INDEX idx_findings_hypothesis ON findings (hypothesis_id);
