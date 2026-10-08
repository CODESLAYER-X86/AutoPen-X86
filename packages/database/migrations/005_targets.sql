-- Targets of an engagement. Application layer validates each target against
-- scope BEFORE insert; out-of-scope targets never reach this table.
CREATE TABLE targets (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    type text NOT NULL,
    value text NOT NULL,
    label text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT targets_type_check CHECK (
        type IN ('URL', 'DOMAIN', 'HOST', 'IP', 'APPLICATION', 'CTF_INSTANCE')
    ),
    CONSTRAINT targets_value_nonempty CHECK (length(value) > 0)
);

CREATE UNIQUE INDEX idx_targets_unique ON targets (engagement_id, type, value);
CREATE INDEX idx_targets_engagement ON targets (engagement_id);
