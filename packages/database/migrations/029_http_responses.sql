-- Part 3 — HTTP response records (spec §17, §48).
-- Bodies live in the evidence store (artifact refs); the row carries
-- metadata, hashes and the EXPLICIT truncation flag (never silently).
CREATE TABLE http_responses (
    id text PRIMARY KEY,
    request_id text NOT NULL REFERENCES http_requests (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    status integer NOT NULL,
    headers jsonb NOT NULL DEFAULT '[]'::jsonb,
    content_type text,
    content_kind text NOT NULL DEFAULT 'UNKNOWN',
    body_artifact_ref text,
    body_sha256 text,
    body_preview text,
    content_length integer NOT NULL DEFAULT 0,
    truncated boolean NOT NULL DEFAULT false,
    timing_ms integer NOT NULL DEFAULT 0,
    redirect_to text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT http_responses_status_check CHECK (status >= 100 AND status <= 599)
);

CREATE INDEX idx_http_responses_request ON http_responses (request_id);
CREATE INDEX idx_http_responses_engagement ON http_responses (engagement_id, created_at DESC);
