-- Part 8 §11: API credentials with full lifecycle (owner, scope, expiry,
-- last use, revocation). No immortal credentials by default.
CREATE TABLE api_credentials (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('API_KEY', 'PERSONAL_ACCESS_TOKEN')),
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    scopes text[] NOT NULL CHECK (array_length(scopes, 1) BETWEEN 1 AND 3),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE INDEX idx_api_credentials_user ON api_credentials (user_id, created_at DESC);
CREATE INDEX idx_api_credentials_status ON api_credentials (status) WHERE status = 'ACTIVE';

-- Part 8 §14-§15: scoped credential grants. A worker can only resolve a
-- credential when the grant matches engagement+identity+target+purpose and
-- has not expired or been revoked.
CREATE TABLE credential_grants (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    identity_id text NOT NULL,
    target_id text NOT NULL,
    secret_reference text NOT NULL,
    purpose text NOT NULL CHECK (purpose IN ('AUTHENTICATION', 'VERIFICATION', 'REPRODUCTION')),
    status text NOT NULL DEFAULT 'ISSUED' CHECK (status IN ('ISSUED', 'EXPIRED', 'REVOKED', 'CONSUMED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    consumed_at timestamptz,
    CONSTRAINT grant_not_consumed_and_revoked CHECK (revoked_at IS NULL OR consumed_at IS NULL)
);

CREATE INDEX idx_credential_grants_lookup
    ON credential_grants (engagement_id, identity_id, target_id, purpose, status);
CREATE INDEX idx_credential_grants_expiry ON credential_grants (expires_at) WHERE status = 'ISSUED';

-- Part 8 §92: scope versions. Every target-bound action references the scope
-- version it executed under; scope changes never mutate history.
CREATE TABLE scope_versions (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    version integer NOT NULL,
    status text NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED', 'ACTIVE', 'SUPERSEDED')),
    scope jsonb NOT NULL,
    diff jsonb NOT NULL,
    created_by text NOT NULL REFERENCES users (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    UNIQUE (engagement_id, version)
);

CREATE UNIQUE INDEX idx_scope_versions_one_active
    ON scope_versions (engagement_id) WHERE status = 'ACTIVE';
CREATE INDEX idx_scope_versions_engagement ON scope_versions (engagement_id, version DESC);
