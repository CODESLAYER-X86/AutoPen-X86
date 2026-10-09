-- Part 4 — Authorization matrix (spec §23, §98).
-- Identity x Endpoint x Object x Action. HTTP 403 is not equated with every
-- possible denial: outcomes are classified explicitly.
CREATE TABLE authorization_matrix (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    endpoint_id text NOT NULL REFERENCES endpoints (id) ON DELETE CASCADE,
    identity_id text,
    object_ref text,
    action text,
    outcome text NOT NULL,
    status_code integer,
    request_id text,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    observation_count integer NOT NULL DEFAULT 1,
    fingerprint text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CONSTRAINT authz_outcome_check CHECK (outcome IN ('ALLOWED','DENIED','REDIRECTED','UNKNOWN','ERROR')),
    CONSTRAINT authz_status_code_range CHECK (status_code IS NULL OR (status_code >= 100 AND status_code <= 599)),
    CONSTRAINT authz_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_authz_endpoint ON authorization_matrix (endpoint_id);
CREATE INDEX idx_authz_identity ON authorization_matrix (engagement_id, identity_id);
CREATE INDEX idx_authz_object ON authorization_matrix (engagement_id, object_ref);
