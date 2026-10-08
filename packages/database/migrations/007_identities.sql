-- Identities for an engagement (Anonymous / User A / User B / Admin ...).
-- Credential material lives in the secret store; only references are stored.
CREATE TABLE identities (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    name text NOT NULL,
    role text NOT NULL DEFAULT '',
    type text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT identities_type_check CHECK (type IN ('ANONYMOUS', 'USER', 'ADMIN', 'SERVICE')),
    CONSTRAINT identities_name_nonempty CHECK (length(name) > 0)
);

CREATE UNIQUE INDEX idx_identities_unique ON identities (engagement_id, name);
