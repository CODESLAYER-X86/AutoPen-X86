-- Part 4 — Parameter registry (spec §14-§18).
-- Semantic classifications are CANDIDATES (§16). Sensitive values are stored
-- redacted; example values are bounded (§114-§115).
CREATE TABLE parameters (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    endpoint_id text REFERENCES endpoints (id) ON DELETE SET NULL,
    fingerprint text NOT NULL,
    name text NOT NULL,
    location text NOT NULL,
    observed_type text,
    example_values jsonb NOT NULL DEFAULT '[]'::jsonb,
    value_characteristics jsonb NOT NULL DEFAULT '[]'::jsonb,
    semantic_candidates jsonb NOT NULL DEFAULT '[]'::jsonb,
    identity_association jsonb NOT NULL DEFAULT '[]'::jsonb,
    is_sensitive boolean NOT NULL DEFAULT false,
    confidence numeric NOT NULL DEFAULT 0.5,
    observation_count integer NOT NULL DEFAULT 1,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT parameters_location_check CHECK (location IN ('QUERY','PATH','JSON','FORM','MULTIPART','HEADER','COOKIE','WEBSOCKET','GRAPHQL','HTML_FORM','JAVASCRIPT')),
    CONSTRAINT parameters_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT parameters_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_parameters_engagement_name ON parameters (engagement_id, name);
CREATE INDEX idx_parameters_endpoint ON parameters (endpoint_id);
