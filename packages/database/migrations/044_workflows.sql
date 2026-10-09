-- Part 4 — Workflow candidates (spec §30, §34-§35).
-- Reconstructed from observed sequences; confidence marks the difference
-- between OBSERVED and INFERRED (inferred never becomes fact automatically).
CREATE TABLE workflows (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    name text NOT NULL,
    status text NOT NULL DEFAULT 'CANDIDATE',
    required_identity text,
    confidence numeric NOT NULL DEFAULT 0.5,
    state_count integer NOT NULL DEFAULT 0,
    transition_count integer NOT NULL DEFAULT 0,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT workflows_status_check CHECK (status IN ('CANDIDATE','CONFIRMED','REJECTED')),
    CONSTRAINT workflows_confidence_range CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX idx_workflows_engagement ON workflows (engagement_id);

CREATE TABLE workflow_states (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    workflow_id text NOT NULL REFERENCES workflows (id) ON DELETE CASCADE,
    name text NOT NULL,
    detection jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed boolean NOT NULL DEFAULT true,
    confidence numeric NOT NULL DEFAULT 0.8,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CONSTRAINT workflow_states_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT workflow_states_name_unique UNIQUE (workflow_id, name)
);

CREATE INDEX idx_workflow_states_workflow ON workflow_states (workflow_id);

CREATE TABLE workflow_transitions (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    workflow_id text NOT NULL REFERENCES workflows (id) ON DELETE CASCADE,
    from_state_id text REFERENCES workflow_states (id) ON DELETE SET NULL,
    to_state_id text NOT NULL REFERENCES workflow_states (id) ON DELETE CASCADE,
    trigger_endpoint_id text REFERENCES endpoints (id) ON DELETE SET NULL,
    trigger_summary text NOT NULL,
    identity_id text,
    observation_kind text NOT NULL DEFAULT 'OBSERVED',
    confidence numeric NOT NULL DEFAULT 0.8,
    occurrence_count integer NOT NULL DEFAULT 1,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CONSTRAINT transitions_kind_check CHECK (observation_kind IN ('OBSERVED','INFERRED')),
    CONSTRAINT transitions_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT transitions_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_workflow_transitions_workflow ON workflow_transitions (workflow_id);
CREATE INDEX idx_workflow_transitions_identity ON workflow_transitions (engagement_id, identity_id);
