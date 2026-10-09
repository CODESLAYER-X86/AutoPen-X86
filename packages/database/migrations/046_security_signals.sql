-- Part 4 — Security signals (spec §42-§43).
-- Signals are NOT findings (§2, §136). Deterministic generation with
-- fingerprint idempotency (§111). Summaries derive from untrusted target
-- data and stay bounded (§114-§115).
CREATE TABLE security_signals (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    signal_type text NOT NULL,
    source text NOT NULL,
    endpoint_id text REFERENCES endpoints (id) ON DELETE SET NULL,
    parameter_id text REFERENCES parameters (id) ON DELETE SET NULL,
    identity_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    object_ref text,
    confidence numeric NOT NULL DEFAULT 0.5,
    summary text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'NEW',
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signals_type_check CHECK (signal_type IN ('AUTH_STATE_CHANGE','OBJECT_IDENTIFIER','CROSS_IDENTITY_DIFFERENCE','CROSS_IDENTITY_OBJECT_REFERENCE','REFLECTED_INPUT','UNEXPECTED_REDIRECT','STATE_TRANSITION_ANOMALY','SENSITIVE_DATA_EXPOSURE','ERROR_DISCLOSURE','UNUSUAL_RESPONSE_DIFFERENCE','CLIENT_CONTROLLED_VALUE','TOKEN_PATTERN','UNEXPECTED_METHOD_BEHAVIOR')),
    CONSTRAINT signals_status_check CHECK (status IN ('NEW','CONSUMED','SUPERSEDED')),
    CONSTRAINT signals_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT signals_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_signals_engagement_status ON security_signals (engagement_id, status, created_at DESC);
CREATE INDEX idx_signals_endpoint ON security_signals (endpoint_id);
CREATE INDEX idx_signals_type ON security_signals (engagement_id, signal_type);
