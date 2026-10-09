-- Part 3 — cookie descriptors (spec §23). VALUES never stored: only an
-- opaque secret-store reference (COOKIE_REF_*).
CREATE TABLE cookies (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    identity_id text,
    name text NOT NULL,
    domain text NOT NULL,
    path text NOT NULL DEFAULT '/',
    secure boolean NOT NULL DEFAULT false,
    http_only boolean NOT NULL DEFAULT false,
    same_site text,
    expiration timestamptz,
    secret_reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cookies_name_nonempty CHECK (length(name) > 0)
);

CREATE INDEX idx_cookies_engagement ON cookies (engagement_id, created_at DESC);
CREATE INDEX idx_cookies_context ON cookies (context_id);
