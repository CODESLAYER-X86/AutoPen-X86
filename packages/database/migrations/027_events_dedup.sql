-- Event idempotency (spec Part 2 §65): events may carry a dedup_key so that
-- recovery replays never duplicate audit records. Postgres unique indexes
-- allow multiple NULLs, so legacy events are unaffected.
ALTER TABLE events ADD COLUMN dedup_key text;

CREATE UNIQUE INDEX idx_events_dedup ON events (dedup_key);
