-- Model call log (spec Part 2 §37-§38): provider-independent TokenUsage
-- persistence per purpose (leader / worker / knowledge / summarization /
-- verification). The QuotaManager reads this for cross-restart accuracy and
-- the scheduler reads it for quota-aware ordering.
CREATE TABLE model_calls (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    run_id text REFERENCES agent_runs (id) ON DELETE CASCADE,
    task_id text REFERENCES tasks (id) ON DELETE SET NULL,
    decision_id text REFERENCES agent_decisions (id) ON DELETE SET NULL,
    role text NOT NULL,
    purpose text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    duration_ms integer,
    status text NOT NULL DEFAULT 'COMPLETED',
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT model_calls_role_check CHECK (role IN ('strategic', 'tactical')),
    CONSTRAINT model_calls_purpose_check CHECK (
        purpose IN ('leader', 'worker', 'knowledge', 'summarization', 'verification')
    ),
    CONSTRAINT model_calls_status_check CHECK (status IN ('COMPLETED', 'FAILED'))
);

CREATE INDEX idx_model_calls_engagement ON model_calls (engagement_id, created_at DESC);
CREATE INDEX idx_model_calls_run ON model_calls (run_id);
CREATE INDEX idx_model_calls_purpose ON model_calls (engagement_id, purpose);
