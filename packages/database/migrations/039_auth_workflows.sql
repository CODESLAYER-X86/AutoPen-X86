-- Part 3 — recorded authentication workflows (spec §28).
-- A login flow observed in the browser, reusable by policy.
CREATE TABLE auth_workflows (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    identity_id text NOT NULL,
    steps jsonb NOT NULL DEFAULT '[]'::jsonb,
    session_id text,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_workflows_engagement ON auth_workflows (engagement_id);
