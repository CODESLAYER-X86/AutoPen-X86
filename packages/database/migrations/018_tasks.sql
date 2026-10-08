-- Tasks (spec Part 2 §13, §18, §19, §36, §65): persistent investigation tasks
-- with explicit dependencies, worker constraints, and idempotent creation.
CREATE TABLE tasks (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    run_id text REFERENCES agent_runs (id) ON DELETE CASCADE,
    decision_id text REFERENCES agent_decisions (id) ON DELETE SET NULL,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    type text NOT NULL,
    objective text NOT NULL,
    worker_type text NOT NULL,
    status text NOT NULL DEFAULT 'CREATED',
    priority double precision NOT NULL DEFAULT 0.5,
    expected_information_gain double precision,
    depends_on jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
    constraints jsonb NOT NULL DEFAULT '{}'::jsonb,
    inputs jsonb NOT NULL DEFAULT '{}'::jsonb,
    result jsonb,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 3,
    failure_code text,
    failure_reason text,
    idempotency_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    CONSTRAINT tasks_status_check CHECK (
        status IN ('CREATED', 'QUEUED', 'READY', 'RUNNING', 'WAITING',
                   'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'EXPIRED', 'RECOVERY_PENDING')
    ),
    CONSTRAINT tasks_worker_type_check CHECK (
        worker_type IN ('HTTP_WORKER', 'BROWSER_WORKER', 'SOURCE_WORKER', 'ANALYSIS_WORKER')
    ),
    CONSTRAINT tasks_priority_range CHECK (priority >= 0 AND priority <= 1),
    CONSTRAINT tasks_idempotency_unique UNIQUE (engagement_id, idempotency_key)
);

ALTER TABLE observations
    ADD CONSTRAINT observations_task_id_fkey
    FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE SET NULL;

CREATE INDEX idx_tasks_engagement ON tasks (engagement_id, status, priority DESC);
CREATE INDEX idx_tasks_run ON tasks (run_id);
CREATE INDEX idx_tasks_hypothesis ON tasks (hypothesis_id);
CREATE INDEX idx_tasks_status ON tasks (status);
