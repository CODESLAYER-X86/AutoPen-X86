-- Agent runs (spec Part 2 §3): one autonomous execution session per run.
CREATE TABLE agent_runs (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'CREATED',
    reason text,
    strategy_version integer,
    leader_model text NOT NULL,
    worker_model text NOT NULL,
    metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at timestamptz,
    ended_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_runs_status_check CHECK (
        status IN ('CREATED', 'INITIALIZING', 'RUNNING', 'PAUSED', 'WAITING', 'COMPLETED', 'FAILED', 'CANCELLED')
    )
);

CREATE INDEX idx_agent_runs_engagement ON agent_runs (engagement_id, created_at DESC);
CREATE INDEX idx_agent_runs_status ON agent_runs (status);
