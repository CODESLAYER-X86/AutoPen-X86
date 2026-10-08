-- Projects group engagements and are owned by a single user.
CREATE TABLE projects (
    id text PRIMARY KEY,
    owner_id text NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_owner ON projects (owner_id, created_at DESC);
