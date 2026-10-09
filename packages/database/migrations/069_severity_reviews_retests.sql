-- Part 7 §17-§18, §67-§68 — Severity assessments, human reviews and retests.
-- CVSS is a deterministic calculator output (§17); the LLM may supply inputs
-- and justification only. Human reviews keep agent_finding, human_review and
-- final_finding CONCEPTUALLY separate (§67) and feed the improvement loop
-- (§68). Retests re-verify the security property, not the raw request (§37).
CREATE TABLE severity_assessments (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    input jsonb NOT NULL,
    severity text NOT NULL,
    source text NOT NULL DEFAULT 'CVSS_CALCULATOR',
    cvss jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT severity_assessment_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT severity_assessment_source_check CHECK (source IN ('CVSS_CALCULATOR', 'HUMAN_OVERRIDE'))
);

CREATE INDEX idx_severity_assessments_finding ON severity_assessments (finding_id, created_at DESC);

-- §67 — human review records. agent_* columns snapshot the agent's original
-- conclusion at review time; resulting_status is what the finding became.
CREATE TABLE finding_reviews (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    agent_status text NOT NULL,
    agent_confidence double precision,
    decision text NOT NULL,
    reviewer text NOT NULL,
    reason text NOT NULL,
    agent_human_disagreement boolean NOT NULL,
    resulting_status text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT finding_review_decision_check CHECK (
        decision IN ('ACCEPT', 'REJECT', 'MODIFY', 'REQUEST_RETEST', 'MARK_DUPLICATE', 'CHANGE_SEVERITY', 'ADD_REMEDIATION')
    )
);

CREATE INDEX idx_finding_reviews_finding ON finding_reviews (finding_id, created_at DESC);
CREATE INDEX idx_finding_reviews_engagement ON finding_reviews (engagement_id, created_at DESC);

-- §37-§38 — retest lifecycle. outcome FIXED / PARTIALLY_FIXED /
-- STILL_PRESENT; the original finding history is preserved.
CREATE TABLE retests (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'OPEN',
    outcome text,
    verification_id text,
    note text,
    requested_by text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CONSTRAINT retest_status_check CHECK (status IN ('NOT_RETESTED', 'OPEN', 'FIXED', 'PARTIALLY_FIXED', 'STILL_PRESENT')),
    CONSTRAINT retest_outcome_check CHECK (outcome IS NULL OR outcome IN ('FIXED', 'PARTIALLY_FIXED', 'STILL_PRESENT'))
);

CREATE INDEX idx_retests_finding ON retests (finding_id, requested_at DESC);
CREATE INDEX idx_retests_engagement ON retests (engagement_id, requested_at DESC);
