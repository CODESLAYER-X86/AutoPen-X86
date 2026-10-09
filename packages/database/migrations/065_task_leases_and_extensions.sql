-- Part 6 §55-§56: task leases. A RUNNING task is owned by exactly one engine
-- instance until its lease expires; a heartbeat extends the lease. Expired
-- leases move the task to RECOVERY_PENDING where the recovery manager picks a
-- policy (safe retry / resume / mark failed / recompile) — potentially
-- state-changing operations are never blindly retried.
ALTER TABLE tasks
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN leased_by text,
    ADD COLUMN heartbeat_at timestamptz;

CREATE INDEX idx_tasks_lease ON tasks (status, lease_expires_at) WHERE status = 'RUNNING';

-- Part 6 §60: the test registry gains experimental verdicts. The Part 2
-- execution status (PENDING/RUNNING/...) stays; `result` records what the
-- experiment concluded about the hypothesis.
ALTER TABLE tests
    ADD COLUMN result text,
    ADD COLUMN expected_signal text,
    ADD COLUMN actual_signal text,
    ADD COLUMN mutation jsonb,
    ADD CONSTRAINT tests_result_check CHECK (
        result IN ('SUPPORTED', 'DISPROVED', 'INCONCLUSIVE', 'BLOCKED', 'FAILED')
    );

-- Part 6 §58: findings gain the confidence model, category, impact,
-- remediation and verification linkage. Confidence is NOT severity (§28).
ALTER TABLE findings
    ADD COLUMN category text,
    ADD COLUMN confidence double precision,
    ADD COLUMN confidence_level text,
    ADD COLUMN confidence_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN impact text,
    ADD COLUMN remediation text,
    ADD COLUMN verification_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN target_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN affected_endpoints jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN affected_identities jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN mode text NOT NULL DEFAULT 'PENTEST';

ALTER TABLE findings DROP CONSTRAINT findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (
    status IN ('PROPOSED', 'CONFIRMED', 'REJECTED', 'CANDIDATE', 'VERIFIED')
);
ALTER TABLE findings ADD CONSTRAINT findings_confidence_level_check CHECK (
    confidence_level IN ('HIGH', 'MEDIUM', 'LOW')
);
ALTER TABLE findings ADD CONSTRAINT findings_confidence_range CHECK (
    confidence IS NULL OR (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX idx_findings_confidence ON findings (engagement_id, confidence_level);
