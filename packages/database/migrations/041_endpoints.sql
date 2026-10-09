-- Part 4 — Endpoint registry (spec §7-§13).
-- Deterministic fingerprints prevent duplicate endpoint records; the
-- canonical path is a CANDIDATE (§7), never a fact. Inferred endpoints are
-- never represented as observed (§12-§13).
CREATE TABLE endpoints (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    scheme text NOT NULL,
    host text NOT NULL,
    port integer NOT NULL,
    path text NOT NULL,
    canonical_path text NOT NULL,
    canonical_confidence numeric NOT NULL DEFAULT 0.5,
    resource_family text,
    api_version text,
    methods jsonb NOT NULL DEFAULT '[]'::jsonb,
    content_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    authentication_observed boolean NOT NULL DEFAULT false,
    identities_observed jsonb NOT NULL DEFAULT '[]'::jsonb,
    status text NOT NULL DEFAULT 'DISCOVERED',
    discovery_source text NOT NULL,
    confidence_category text NOT NULL DEFAULT 'OBSERVED',
    confidence numeric NOT NULL DEFAULT 0.5,
    observed_urls jsonb NOT NULL DEFAULT '[]'::jsonb,
    observation_count integer NOT NULL DEFAULT 0,
    signal_count integer NOT NULL DEFAULT 0,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    merged_into text,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT endpoints_status_check CHECK (status IN ('DISCOVERED','OBSERVED','MAPPED','TESTING','INTERESTING','VERIFIED','IGNORED')),
    CONSTRAINT endpoints_source_check CHECK (discovery_source IN ('BROWSER_NAVIGATION','BROWSER_NETWORK','HTML','FORM','JAVASCRIPT','WEBSOCKET','ROBOTS_TXT','SITEMAP','API_SPECIFICATION','IMPORTED_TRAFFIC','USER_INPUT','KNOWLEDGE_INFERENCE')),
    CONSTRAINT endpoints_confidence_category_check CHECK (confidence_category IN ('OBSERVED','STRONGLY_INFERRED','INFERRED','UNVERIFIED')),
    CONSTRAINT endpoints_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT endpoints_canonical_confidence_range CHECK (canonical_confidence >= 0 AND canonical_confidence <= 1),
    CONSTRAINT endpoints_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_endpoints_engagement_status ON endpoints (engagement_id, status);
CREATE INDEX idx_endpoints_host ON endpoints (engagement_id, host);
CREATE INDEX idx_endpoints_family ON endpoints (engagement_id, resource_family);
