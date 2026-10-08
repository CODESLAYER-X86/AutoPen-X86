-- Platform users (operators). IDs are application-generated prefixed ids.
CREATE TABLE users (
    id text PRIMARY KEY,
    email text NOT NULL UNIQUE,
    name text NOT NULL,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'USER',
    last_login_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_role_check CHECK (role IN ('USER', 'ADMIN'))
);

CREATE INDEX idx_users_email ON users (email);
