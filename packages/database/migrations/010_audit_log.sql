-- Audit trail for security-sensitive operations (spec §30).
-- Complements `events`: events = system telemetry, audit = who did what.
CREATE TABLE audit_log (
    id text PRIMARY KEY,
    actor_user_id text REFERENCES users (id) ON DELETE SET NULL,
    action text NOT NULL,
    resource text NOT NULL,
    resource_id text,
    engagement_id text REFERENCES engagements (id) ON DELETE CASCADE,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_engagement ON audit_log (engagement_id, created_at DESC);
CREATE INDEX idx_audit_actor ON audit_log (actor_user_id, created_at DESC);
CREATE INDEX idx_audit_action ON audit_log (action);
