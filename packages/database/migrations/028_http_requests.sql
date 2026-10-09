-- Part 3 — HTTP traffic records (spec §16-§18, §55, §66).
-- The normalized request representation shared by the HTTP engine AND
-- browser capture (§14). Sensitive header values are REDACTED before
-- storage (raw bundles live in the evidence store).
CREATE TABLE http_requests (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text,
    identity_id text,
    method text NOT NULL,
    url text NOT NULL,
    normalized_url text NOT NULL,
    normalized_fingerprint text NOT NULL,
    headers jsonb NOT NULL DEFAULT '[]'::jsonb,
    query jsonb NOT NULL DEFAULT '[]'::jsonb,
    body_type text,
    body_parsed jsonb,
    body_artifact_ref text,
    body_sha256 text,
    body_bytes integer NOT NULL DEFAULT 0,
    source text NOT NULL,
    provenance_source text NOT NULL,
    provenance_parent_task_id text,
    provenance_hypothesis_id text,
    provenance_test_id text,
    provenance_reason text,
    parent_request_id text,
    browser_context_id text,
    browser_page_id text,
    correlation_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT http_requests_source_check CHECK (source IN ('BROWSER', 'HTTP_WORKER', 'IMPORTED', 'REPLAY')),
    CONSTRAINT http_requests_method_check CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'))
);

CREATE INDEX idx_http_requests_engagement ON http_requests (engagement_id, created_at DESC);
CREATE INDEX idx_http_requests_task ON http_requests (task_id);
CREATE INDEX idx_http_requests_fingerprint ON http_requests (engagement_id, normalized_fingerprint);
CREATE INDEX idx_http_requests_parent ON http_requests (parent_request_id);
