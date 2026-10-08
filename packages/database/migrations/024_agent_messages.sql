-- Agent messages (spec Part 2 §2 AgentMessage, §60-§62): persisted prompt /
-- response audit trail. `untrusted_bytes` records how much target-derived
-- content was rendered inside explicit untrusted delimiters — the audit
-- answer to "was target data kept semantically separate?".
CREATE TABLE agent_messages (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    run_id text REFERENCES agent_runs (id) ON DELETE CASCADE,
    task_id text REFERENCES tasks (id) ON DELETE SET NULL,
    channel text NOT NULL,
    direction text NOT NULL,
    role text NOT NULL,
    content text NOT NULL,
    untrusted_bytes integer NOT NULL DEFAULT 0,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    input_tokens integer,
    output_tokens integer,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_messages_channel_check CHECK (channel IN ('LEADER', 'WORKER')),
    CONSTRAINT agent_messages_direction_check CHECK (direction IN ('OUTBOUND', 'INBOUND')),
    CONSTRAINT agent_messages_role_check CHECK (role IN ('system', 'user', 'assistant'))
);

CREATE INDEX idx_agent_messages_run ON agent_messages (run_id, created_at);
CREATE INDEX idx_agent_messages_engagement ON agent_messages (engagement_id, created_at DESC);
CREATE INDEX idx_agent_messages_task ON agent_messages (task_id);
