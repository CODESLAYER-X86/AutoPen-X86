-- Part 6 §48-§49: human approval records for high-risk actions. When the
-- deterministic policy returns REQUIRE_USER_APPROVAL the task moves to
-- WAITING and an approval row is created. Approvals are decided exactly once
-- (decided_at is set under a guard clause) and the decision is auditable.
CREATE TABLE engagement_approvals (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text REFERENCES tasks (id) ON DELETE CASCADE,
    risk text NOT NULL DEFAULT 'HIGH',
    action_summary text NOT NULL,
    requested_by text NOT NULL DEFAULT 'engine',
    decided_by text,
    decision text,
    decided_reason text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    decided_at timestamptz,
    CONSTRAINT approval_risk_check CHECK (risk IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT approval_decision_check CHECK (
        decision IS NULL OR decision IN ('APPROVED', 'REJECTED')
    ),
    -- An approval is decided exactly once (§49: deterministic policy).
    CONSTRAINT approval_single_decision UNIQUE (id) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_approvals_engagement ON engagement_approvals (engagement_id, decided_at);
CREATE INDEX idx_approvals_pending ON engagement_approvals (engagement_id) WHERE decision IS NULL;

-- Part 6 §79: benchmark runs. Each row records the metrics of one benchmark
-- engagement executed by the evaluation framework.
CREATE TABLE benchmark_runs (
    id text PRIMARY KEY,
    benchmark text NOT NULL,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    outcome text NOT NULL,
    metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT benchmark_outcome_check CHECK (
        outcome IN ('COMPLETED', 'SOLVED', 'STOPPED', 'FAILED')
    )
);

CREATE INDEX idx_benchmark_runs ON benchmark_runs (benchmark, started_at DESC);
