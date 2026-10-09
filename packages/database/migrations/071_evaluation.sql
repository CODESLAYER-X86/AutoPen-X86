-- Part 7 §59 — Evaluation database. Benchmark scores are NEVER stored only
-- as a final JSON blob: runs, scenarios, expected (ground-truth) findings,
-- observed findings, metric rows, events and model configs are all queryable.
CREATE TABLE evaluation_runs (
    id text PRIMARY KEY,
    status text NOT NULL DEFAULT 'RUNNING',
    config jsonb NOT NULL,
    started_by text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    error text,
    is_golden boolean NOT NULL DEFAULT false,
    golden_reference text REFERENCES evaluation_runs (id),
    CONSTRAINT evaluation_run_status_check CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'STOPPED'))
);

CREATE INDEX idx_evaluation_runs ON evaluation_runs (started_at DESC);
CREATE INDEX idx_evaluation_runs_golden ON evaluation_runs (is_golden) WHERE is_golden;

-- Scenario definitions are seeded and versioned (§58: scenario version is
-- part of the reproducibility snapshot).
CREATE TABLE evaluation_scenarios (
    id text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    description text NOT NULL,
    fixture text NOT NULL,
    expected_observations jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_hypotheses jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_stop_condition text,
    safety_expectations jsonb NOT NULL DEFAULT '[]'::jsonb,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evaluation_scenario_kind_check CHECK (
        kind IN (
            'RECON', 'AUTHENTICATION', 'AUTHORIZATION', 'SESSION', 'INPUT_VALIDATION',
            'BUSINESS_LOGIC', 'WORKFLOW_STATE', 'CLIENT_SIDE', 'API', 'WEBSOCKET',
            'SOURCE_ANALYSIS', 'MULTI_IDENTITY', 'DIFFERENTIAL', 'CTF_REASONING',
            'HALLUCINATION', 'SCOPE_SAFETY', 'PROMPT_INJECTION', 'REPETITION',
            'RESOURCE_AWARENESS', 'REPLANNING', 'CONTRADICTORY_EVIDENCE', 'HONESTY'
        )
    )
);

CREATE UNIQUE INDEX idx_evaluation_scenarios_name ON evaluation_scenarios (name, version);
CREATE INDEX idx_evaluation_scenarios_kind ON evaluation_scenarios (kind);

-- §41 — ground truth, hidden from the agent.
CREATE TABLE evaluation_expected_findings (
    id text PRIMARY KEY,
    scenario_id text NOT NULL REFERENCES evaluation_scenarios (id) ON DELETE CASCADE,
    endpoint text NOT NULL,
    finding_category text NOT NULL,
    severity text NOT NULL,
    verification_required boolean NOT NULL DEFAULT true,
    match_tokens jsonb NOT NULL,
    description text NOT NULL,
    CONSTRAINT expected_finding_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX idx_evaluation_expected ON evaluation_expected_findings (scenario_id);

-- §59 — observed findings matched against ground truth (TP / FP / FN / DUP).
CREATE TABLE evaluation_observed_findings (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    scenario_id text NOT NULL REFERENCES evaluation_scenarios (id) ON DELETE CASCADE,
    expected_finding_id text REFERENCES evaluation_expected_findings (id) ON DELETE SET NULL,
    finding_id text NOT NULL,
    outcome text NOT NULL,
    matched_tokens jsonb NOT NULL DEFAULT '[]'::jsonb,
    category text NOT NULL,
    CONSTRAINT observed_finding_outcome_check CHECK (outcome IN ('TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE', 'DUPLICATE'))
);

CREATE INDEX idx_evaluation_observed_run ON evaluation_observed_findings (run_id);
CREATE INDEX idx_evaluation_observed_scenario ON evaluation_observed_findings (scenario_id);

-- §59 — queryable metric rows (scope: run | scenario | category | dimension).
CREATE TABLE evaluation_metrics (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    scenario_id text REFERENCES evaluation_scenarios (id) ON DELETE CASCADE,
    metric text NOT NULL,
    scope text NOT NULL DEFAULT 'run',
    value double precision NOT NULL,
    unit text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_evaluation_metrics_run ON evaluation_metrics (run_id, scope);
CREATE INDEX idx_evaluation_metrics_name ON evaluation_metrics (run_id, metric);

-- §59 — evaluation events (the audit chain of the run itself, incl. safety
-- observations like prompt-injection containment, §78).
CREATE TABLE evaluation_events (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    scenario_id text REFERENCES evaluation_scenarios (id) ON DELETE CASCADE,
    type text NOT NULL,
    description text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_evaluation_events_run ON evaluation_events (run_id, occurred_at);

-- §55-§58 — model configuration snapshots for A/B comparisons: same target,
-- scope, tool capabilities, budget and benchmark; everything recorded.
CREATE TABLE evaluation_model_configs (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    label text NOT NULL,
    strategic_model text NOT NULL,
    tactical_model text NOT NULL,
    prompt_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    tool_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    knowledge_index_version text,
    budget jsonb NOT NULL DEFAULT '{}'::jsonb,
    random_seed bigint,
    agent_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_evaluation_model_configs_run ON evaluation_model_configs (run_id);

-- §88-§89 — regression checks with configurable thresholds; release gates
-- require zero scope violations and zero unsupported claims.
CREATE TABLE evaluation_regression_checks (
    id text PRIMARY KEY,
    run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    baseline_run_id text NOT NULL REFERENCES evaluation_runs (id) ON DELETE CASCADE,
    verdict text NOT NULL,
    thresholds jsonb NOT NULL,
    deltas jsonb NOT NULL DEFAULT '{}'::jsonb,
    failures jsonb NOT NULL DEFAULT '[]'::jsonb,
    checked_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT regression_verdict_check CHECK (verdict IN ('PASS', 'FAIL', 'WARN'))
);

CREATE INDEX idx_regression_checks_run ON evaluation_regression_checks (run_id, checked_at DESC);
