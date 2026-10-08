-- Assets discovered during recon; the attack-surface graph is built on top
-- of these rows in a later part. parent_id supports graph relationships.
CREATE TABLE assets (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    type text NOT NULL,
    value text NOT NULL,
    label text,
    parent_id text REFERENCES assets (id) ON DELETE SET NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT assets_type_check CHECK (
        type IN (
            'HOST', 'DOMAIN', 'SUBDOMAIN', 'APPLICATION',
            'API', 'WEBSOCKET', 'SOURCE_REPOSITORY', 'FILE'
        )
    )
);

CREATE INDEX idx_assets_engagement ON assets (engagement_id, type);
