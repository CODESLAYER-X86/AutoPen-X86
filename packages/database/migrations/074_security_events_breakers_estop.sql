-- Part 8 §94-§96: incidents and security events form the incident timeline.
CREATE TABLE incidents (
    id text PRIMARY KEY,
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED')),
    severity text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title text NOT NULL,
    opened_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE INDEX idx_incidents_status ON incidents (status, opened_at DESC) WHERE status <> 'RESOLVED';

-- Events are append-only at the repository layer: the only mutation is
-- linking a row to an incident. No update/delete methods are exposed.
CREATE TABLE security_events (
    id text PRIMARY KEY,
    incident_id text REFERENCES incidents (id) ON DELETE SET NULL,
    severity text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    category text NOT NULL,
    actor text NOT NULL CHECK (actor IN ('AGENT', 'MODEL', 'WORKER', 'USER', 'PLATFORM')),
    engagement_id text REFERENCES engagements (id) ON DELETE SET NULL,
    description text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_security_events_severity ON security_events (severity, created_at DESC);
CREATE INDEX idx_security_events_engagement ON security_events (engagement_id, created_at DESC);
CREATE INDEX idx_security_events_incident ON security_events (incident_id) WHERE incident_id IS NOT NULL;

-- Part 8 §98-§99: circuit breaker state rows. Deterministic counters; the
-- breaker pauses the subject (agent or model configuration) when the
-- violation threshold is reached and requires a human reset.
CREATE TABLE circuit_breakers (
    id text PRIMARY KEY,
    subject text NOT NULL CHECK (subject IN ('AGENT', 'MODEL')),
    subject_id text NOT NULL,
    engagement_id text REFERENCES engagements (id) ON DELETE CASCADE,
    category text NOT NULL CHECK (category IN (
        'SCOPE_VIOLATION', 'INVALID_TOOL_REQUEST', 'CREDENTIAL_REQUEST',
        'RESOURCE_ABUSE', 'DUPLICATE_EXECUTION', 'INVALID_MODEL_OUTPUT',
        'MODEL_POLICY_BYPASS')),
    state text NOT NULL DEFAULT 'CLOSED' CHECK (state IN ('CLOSED', 'OPEN', 'HALF_OPEN')),
    violation_count integer NOT NULL DEFAULT 0,
    threshold integer NOT NULL,
    tripped_at timestamptz,
    reset_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (subject, subject_id, category)
);

CREATE INDEX idx_circuit_breakers_open ON circuit_breakers (subject, category) WHERE state = 'OPEN';

-- Part 8 §89-§90: platform emergency stop. Single row; engages globally and
-- deterministically (never depends on the LLM).
CREATE TABLE emergency_stop (
    id text PRIMARY KEY DEFAULT 'EST_PLATFORM',
    status text NOT NULL DEFAULT 'CLEAR' CHECK (status IN ('CLEAR', 'ENGAGED', 'RELEASING')),
    engaged_at timestamptz,
    released_at timestamptz,
    engaged_by text REFERENCES users (id) ON DELETE SET NULL,
    reason text,
    cancelled_tasks integer NOT NULL DEFAULT 0,
    revoked_grants integer NOT NULL DEFAULT 0
);

INSERT INTO emergency_stop (id, status) VALUES ('EST_PLATFORM', 'CLEAR');
