-- Part 5 — Knowledge source registry (spec Part 5 §5-§6, §3-§4, §80).
-- Curated, query-driven, bounded: sources are configured, never crawled
-- aggressively (§28, §81). Trust is a RANKING factor, never a policy
-- override (§6).
CREATE TABLE knowledge_sources (
    id text PRIMARY KEY,
    name text NOT NULL,
    type text NOT NULL,
    base_url text NOT NULL,
    trust_level text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    update_strategy text NOT NULL DEFAULT 'MANUAL',
    crawl_policy jsonb NOT NULL DEFAULT '{"allowed_domains":[],"blocked_domains":[],"entry_paths":[],"respect_robots":true}'::jsonb,
    license_notes text,
    last_synced timestamptz,
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT knowledge_sources_name_unique UNIQUE (name),
    CONSTRAINT knowledge_sources_type_check CHECK (type IN ('OFFICIAL_SECURITY','SECURITY_TRAINING','STANDARDS','TECHNICAL_DOCUMENTATION','SECURITY_RESEARCH','CTF_WRITEUPS','CHALLENGE_REPOSITORIES','CASE_MEMORY','LIVE_WEB')),
    CONSTRAINT knowledge_sources_trust_check CHECK (trust_level IN ('OFFICIAL','TRUSTED_TRAINING','RESEARCH','CTF','COMMUNITY','UNTRUSTED')),
    CONSTRAINT knowledge_sources_strategy_check CHECK (update_strategy IN ('MANUAL','SCHEDULED','ON_DEMAND','INCREMENTAL'))
);

CREATE INDEX idx_knowledge_sources_enabled ON knowledge_sources (enabled, type);
