-- Part 3 — sessions: track why a session left ACTIVE (spec §27).
ALTER TABLE sessions ADD COLUMN status_reason text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS engagement_id text REFERENCES engagements (id) ON DELETE CASCADE;
UPDATE sessions SET engagement_id = (
    SELECT i.engagement_id FROM identities i WHERE i.id = sessions.identity_id
) WHERE engagement_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_engagement ON sessions (engagement_id);
