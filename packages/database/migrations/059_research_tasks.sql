-- Part 5 — Research tasks + selected sources (spec §71-§72, §83, §85).
-- Live research is a bounded, budgeted, fully audited workflow: the task
-- row records question, hypothesis, constraints, budgets and outcome; each
-- candidate source considered is retained with its selection/fetch state.
CREATE TABLE research_tasks (
    id text PRIMARY KEY,
    engagement_id text,
    requested_by text NOT NULL,
    question text NOT NULL,
    hypothesis text,
    required_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    source_constraints jsonb NOT NULL DEFAULT '[]'::jsonb,
    mode text NOT NULL DEFAULT 'CURATED_WEB',
    status text NOT NULL DEFAULT 'PENDING',
    max_sources integer NOT NULL DEFAULT 5,
    max_tokens integer NOT NULL DEFAULT 4000,
    deadline_ms integer NOT NULL DEFAULT 60000,
    started_at timestamptz,
    completed_at timestamptz,
    error text,
    result jsonb,
    tokens_consumed integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT research_tasks_mode_check CHECK (mode IN ('LOCAL_ONLY','CURATED_WEB','OPEN_RESEARCH','CTF_RESEARCH')),
    CONSTRAINT research_tasks_status_check CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','CANCELLED')),
    CONSTRAINT research_tasks_sources_range CHECK (max_sources >= 1 AND max_sources <= 10),
    CONSTRAINT research_tasks_tokens_range CHECK (max_tokens >= 200 AND max_tokens <= 20000)
);

CREATE INDEX idx_research_tasks_engagement ON research_tasks (engagement_id, created_at DESC);

CREATE TABLE research_sources (
    id text PRIMARY KEY,
    research_task_id text NOT NULL REFERENCES research_tasks (id) ON DELETE CASCADE,
    document_id text REFERENCES knowledge_documents (id) ON DELETE SET NULL,
    url text NOT NULL,
    domain text NOT NULL,
    trust_level text NOT NULL DEFAULT 'UNTRUSTED',
    rank integer NOT NULL DEFAULT 0,
    selected boolean NOT NULL DEFAULT false,
    fetch_status text,
    fetched_bytes integer NOT NULL DEFAULT 0,
    fetched_at timestamptz,
    reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT research_sources_trust_check CHECK (trust_level IN ('OFFICIAL','TRUSTED_TRAINING','RESEARCH','CTF','COMMUNITY','UNTRUSTED'))
);

CREATE INDEX idx_research_sources_task ON research_sources (research_task_id, rank);
