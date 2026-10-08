-- Task attempts / worker runs (spec Part 2 §2): one row per worker execution
-- attempt, including token usage, tool call count and structured output.
CREATE TABLE task_attempts (
    id text PRIMARY KEY,
    task_id text NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    attempt integer NOT NULL,
    worker_type text NOT NULL,
    worker_model text NOT NULL,
    status text NOT NULL,
    output jsonb,
    error_code text,
    error_message text,
    tool_calls integer NOT NULL DEFAULT 0,
    network_requests integer NOT NULL DEFAULT 0,
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    duration_ms integer,
    started_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    CONSTRAINT task_attempts_attempt_unique UNIQUE (task_id, attempt)
);

CREATE INDEX idx_task_attempts_task ON task_attempts (task_id, attempt);
CREATE INDEX idx_task_attempts_engagement ON task_attempts (engagement_id, started_at DESC);
