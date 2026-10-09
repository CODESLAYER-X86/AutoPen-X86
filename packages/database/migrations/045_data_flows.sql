-- Part 4 — Data-flow records (spec §37-§41).
-- SOURCE -> TRANSFORMATION -> SINK relationships with correlation kind and
-- confidence. Never claims semantic transformation without evidence (§39).
CREATE TABLE data_flows (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    source jsonb NOT NULL,
    transformations jsonb NOT NULL DEFAULT '[]'::jsonb,
    sink jsonb NOT NULL,
    correlation text NOT NULL,
    confidence numeric NOT NULL DEFAULT 0.5,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT data_flows_correlation_check CHECK (correlation IN ('FORM_TO_REQUEST','SCRIPT_TO_ENDPOINT','STORAGE_TO_REQUEST','INPUT_TO_OUTPUT','WS_REQUEST_RESPONSE')),
    CONSTRAINT data_flows_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT data_flows_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_data_flows_engagement ON data_flows (engagement_id, created_at DESC);
CREATE INDEX idx_data_flows_endpoint ON data_flows (engagement_id, ((source->>'endpoint_id')));
