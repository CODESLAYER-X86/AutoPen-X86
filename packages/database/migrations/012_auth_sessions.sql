-- PLATFORM-side authentication sessions (UI/API login tokens).
-- Only the SHA-256 of the bearer token is stored.
CREATE TABLE auth_sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash char(64) NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX idx_auth_sessions_user ON auth_sessions (user_id);
