-- Part 4 — Object candidates (spec §19, §96-§97).
-- An identifier existing is never an authorization vulnerability by itself
-- (§19); these are candidates with owner attribution and lifecycle evidence.
CREATE TABLE object_candidates (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL DEFAULT 'RESOURCE',
    parameter_id text REFERENCES parameters (id) ON DELETE SET NULL,
    endpoint_id text REFERENCES endpoints (id) ON DELETE SET NULL,
    example_values jsonb NOT NULL DEFAULT '[]'::jsonb,
    owner_identity_id text,
    lifecycle jsonb NOT NULL DEFAULT '{}'::jsonb,
    confidence numeric NOT NULL DEFAULT 0.5,
    observation_count integer NOT NULL DEFAULT 1,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    fingerprint text NOT NULL,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT objects_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT objects_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_objects_engagement_name ON object_candidates (engagement_id, name);
CREATE INDEX idx_objects_owner ON object_candidates (engagement_id, owner_identity_id);
