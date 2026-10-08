-- Leader decisions + decision cycles (spec Part 2 §9, §31). Every strategic
-- model call is persisted: the validated structured decision, its rationale,
-- the input state hash (reproducibility), and the cycle outcome.
CREATE TABLE agent_decisions (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES agent_runs (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    cycle integer NOT NULL,
    input_state_hash text NOT NULL,
    decision_type text NOT NULL,
    reasoning_summary text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    validation_status text NOT NULL DEFAULT 'PENDING',
    rejection_code text,
    rejection_details jsonb,
    cycle_outcome jsonb,
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    duration_ms integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_decisions_validation_check CHECK (
        validation_status IN ('PENDING', 'VALID', 'REJECTED', 'FAILED')
    ),
    CONSTRAINT agent_decisions_cycle_unique UNIQUE (run_id, cycle)
);

CREATE INDEX idx_agent_decisions_run ON agent_decisions (run_id, cycle);
CREATE INDEX idx_agent_decisions_engagement ON agent_decisions (engagement_id, created_at DESC);
