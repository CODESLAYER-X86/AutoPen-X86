-- Scope: first-class, one row per engagement. Enforced deterministically in
-- code by the ScopeChecker; the database stores the authoritative rules.
CREATE TABLE scope (
    id text PRIMARY KEY,
    engagement_id text NOT NULL UNIQUE REFERENCES engagements (id) ON DELETE CASCADE,
    allowed_hosts text[] NOT NULL DEFAULT '{}',
    allowed_domains text[] NOT NULL DEFAULT '{}',
    allowed_ports integer[] NOT NULL DEFAULT '{}',
    allowed_schemes text[] NOT NULL DEFAULT '{http,https}',
    excluded_hosts text[] NOT NULL DEFAULT '{}',
    excluded_paths text[] NOT NULL DEFAULT '{}',
    rate_limit integer,
    concurrency_limit integer,
    destructive_actions_allowed boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scope_schemes_check CHECK (
        allowed_schemes <@ ARRAY['http', 'https', 'ws', 'wss']::text[]
    )
);
