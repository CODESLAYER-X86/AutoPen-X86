-- Part 3 — tool execution audit log (spec §44-§45, §78).
-- Records every gateway tool execution with version + configuration info
-- for reproducibility; inputs are redacted.
CREATE TABLE tool_executions (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text,
    identity_id text,
    tool_name text NOT NULL,
    tool_version text NOT NULL,
    configuration_version text NOT NULL DEFAULT '0',
    correlation_id text,
    status text NOT NULL,
    input_redacted jsonb,
    output_summary jsonb,
    error jsonb,
    duration_ms integer NOT NULL DEFAULT 0,
    deadline_ms integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tool_executions_status_check CHECK (status IN ('SUCCEEDED','FAILED'))
);

CREATE INDEX idx_tool_executions_engagement ON tool_executions (engagement_id, created_at DESC);
CREATE INDEX idx_tool_executions_task ON tool_executions (task_id);
