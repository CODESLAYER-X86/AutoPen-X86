-- TARGET-side sessions: cookies/JWTs/API keys used to interact with the
-- application under test. `secret_reference` points into the secret store.
-- The plaintext credential never enters the database or model context.
CREATE TABLE sessions (
    id text PRIMARY KEY,
    identity_id text NOT NULL REFERENCES identities (id) ON DELETE CASCADE,
    type text NOT NULL,
    status text NOT NULL DEFAULT 'ACTIVE',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret_reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sessions_type_check CHECK (type IN ('COOKIE', 'JWT', 'API_KEY', 'BASIC', 'OAUTH', 'CUSTOM')),
    CONSTRAINT sessions_status_check CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'INVALID'))
);

CREATE INDEX idx_sessions_identity ON sessions (identity_id);
CREATE INDEX idx_sessions_status ON sessions (status);
