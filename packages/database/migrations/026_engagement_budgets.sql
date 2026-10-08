-- Engagement resource budgets + usage counters (spec Part 2 §66). Limits are
-- per engagement and enforced deterministically by the orchestrator/policy;
-- counters track actual usage across agent runs.
CREATE TABLE engagement_budgets (
    id text PRIMARY KEY,
    engagement_id text NOT NULL UNIQUE REFERENCES engagements (id) ON DELETE CASCADE,
    max_duration_seconds integer,
    max_network_requests integer,
    max_concurrent_requests integer,
    max_browser_contexts integer,
    max_model_calls integer,
    max_model_tokens integer,
    max_storage_bytes bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE engagement_usage (
    engagement_id text NOT NULL PRIMARY KEY REFERENCES engagements (id) ON DELETE CASCADE,
    network_requests integer NOT NULL DEFAULT 0,
    concurrent_requests integer NOT NULL DEFAULT 0,
    browser_contexts integer NOT NULL DEFAULT 0,
    model_calls integer NOT NULL DEFAULT 0,
    input_tokens integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    storage_bytes bigint NOT NULL DEFAULT 0,
    tool_calls integer NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_engagement_budgets_engagement ON engagement_budgets (engagement_id);
