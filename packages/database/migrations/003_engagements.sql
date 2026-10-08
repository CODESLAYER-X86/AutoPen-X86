-- Engagements: one authorized testing/CTF run against a defined scope.
CREATE TABLE engagements (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name text NOT NULL,
    mode text NOT NULL,
    status text NOT NULL DEFAULT 'DRAFT',
    description text NOT NULL DEFAULT '',
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT engagements_mode_check CHECK (mode IN ('PENTEST', 'CTF')),
    CONSTRAINT engagements_status_check CHECK (
        status IN ('DRAFT', 'READY', 'RUNNING', 'PAUSED', 'COMPLETED', 'FAILED', 'CANCELLED')
    )
);

CREATE INDEX idx_engagements_project ON engagements (project_id, created_at DESC);
CREATE INDEX idx_engagements_status ON engagements (status);
