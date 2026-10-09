-- Part 7 §7-§14 — Verification planning & results. Verification is a SEPARATE
-- system from discovery (§2): the planner records the chosen strategies,
-- controls, expected result and required evidence; the sufficiency gate (§7)
-- is evaluated BEFORE verification may start; results preserve supporting AND
-- contradictory evidence plus tested alternative explanations (§10).
CREATE TABLE verification_plans (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    strategies jsonb NOT NULL,
    controls jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_result jsonb NOT NULL DEFAULT '{}'::jsonb,
    required_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    sufficiency jsonb NOT NULL,
    status text NOT NULL DEFAULT 'PLANNED',
    result_id text,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT verification_plan_status_check CHECK (status IN ('PLANNED', 'EXECUTING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX idx_verification_plans_finding ON verification_plans (finding_id, created_at DESC);
CREATE INDEX idx_verification_plans_engagement ON verification_plans (engagement_id, created_at DESC);

-- Part 7 §14 — verification results. `status` is the internal verdict
-- (VERIFIED / REJECTED / INCONCLUSIVE); the REPORTED status stays binary
-- (VERIFIED / NOT_VERIFIED, §75). Alternative explanations, including
-- SURVIVING ones, are preserved — a simpler surviving explanation blocks
-- confirmation (§10).
CREATE TABLE verification_results (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    plan_id text NOT NULL REFERENCES verification_plans (id) ON DELETE CASCADE,
    status text NOT NULL,
    confidence double precision NOT NULL,
    supporting_evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    contradictory_evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    reproduced boolean NOT NULL DEFAULT false,
    alternative_explanations jsonb NOT NULL DEFAULT '[]'::jsonb,
    reasoning_summary text NOT NULL,
    completed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT verification_result_status_check CHECK (status IN ('VERIFIED', 'REJECTED', 'INCONCLUSIVE')),
    CONSTRAINT verification_result_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX idx_verification_results_finding ON verification_results (finding_id, completed_at DESC);
CREATE INDEX idx_verification_results_engagement ON verification_results (engagement_id, completed_at DESC);

-- §37 — reproduction plans are stored as CONTROLLED step references
-- (browser action / HTTP request / identity switch / observation), never as
-- arbitrary executable scripts (§12).
CREATE TABLE reproduction_plans (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    prerequisites jsonb NOT NULL DEFAULT '[]'::jsonb,
    steps jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_signals jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_reproduction_plans_finding ON reproduction_plans (finding_id, created_at DESC);
