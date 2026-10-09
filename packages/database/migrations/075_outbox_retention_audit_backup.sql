-- Part 8 §44-§45: transactional outbox. Domain events are persisted in the
-- same transaction as the state change, then delivered by a publisher; the
-- sequence column provides deterministic ordering that does not rely on
-- wall-clock timestamps.
CREATE TABLE outbox_events (
    id text PRIMARY KEY,
    event_type text NOT NULL,
    engagement_id text REFERENCES engagements (id) ON DELETE SET NULL,
    aggregate_id text NOT NULL,
    causation_id text,
    correlation_id text,
    sequence bigint NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED', 'ABANDONED')),
    attempts integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    UNIQUE (aggregate_id, sequence)
);

CREATE INDEX idx_outbox_pending ON outbox_events (created_at) WHERE status = 'PENDING';

-- Part 8 §59-§60: retention policies per data class. Controlled deletion:
-- audit records are retained by policy, never silently erased by sweeps.
CREATE TABLE retention_policies (
    id text PRIMARY KEY,
    data_class text NOT NULL UNIQUE CHECK (data_class IN (
        'RAW_HTTP', 'SCREENSHOTS', 'BROWSER_TRACES', 'HAR', 'SOURCE_ARTIFACTS',
        'REPORTS', 'AGENT_TRACES', 'LOGS', 'EVALUATION_DATA')),
    retention_days integer NOT NULL CHECK (retention_days BETWEEN 0 AND 36500),
    hard_delete boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Safe defaults (§59: do not retain sensitive target data forever).
INSERT INTO retention_policies (id, data_class, retention_days, hard_delete) VALUES
    ('RTP_RAW_HTTP', 'RAW_HTTP', 90, true),
    ('RTP_SCREENSHOTS', 'SCREENSHOTS', 90, true),
    ('RTP_BROWSER_TRACES', 'BROWSER_TRACES', 60, true),
    ('RTP_HAR', 'HAR', 60, true),
    ('RTP_SOURCE_ARTIFACTS', 'SOURCE_ARTIFACTS', 180, true),
    ('RTP_REPORTS', 'REPORTS', 3650, false),
    ('RTP_AGENT_TRACES', 'AGENT_TRACES', 180, true),
    ('RTP_LOGS', 'LOGS', 90, false),
    ('RTP_EVALUATION_DATA', 'EVALUATION_DATA', 365, false);

-- Part 8 §85: tamper-evident audit chain. Each audit row stores the SHA-256
-- of its canonical content chained to the previous row's hash (computed in
-- Node — the platform never depends on pgcrypto being available). Existing
-- rows are numbered deterministically; hash backfill happens lazily in the
-- repository on first append/verify.
ALTER TABLE audit_log
    ADD COLUMN chain_seq bigint,
    ADD COLUMN prev_hash text,
    ADD COLUMN content_hash text;

-- Number any pre-existing rows deterministically (created_at, id order).
WITH ordered AS (
    SELECT id, row_number() OVER (ORDER BY created_at ASC, id ASC) AS seq
    FROM audit_log
)
UPDATE audit_log a
   SET chain_seq = o.seq
  FROM ordered o
 WHERE a.id = o.id;

-- Rows inserted after this migration always carry an explicit chain_seq.
ALTER TABLE audit_log ALTER COLUMN chain_seq SET NOT NULL;
CREATE UNIQUE INDEX idx_audit_chain_seq ON audit_log (chain_seq);

-- Part 8 §62: backup records (created by scripts/ops/backup.ts, verified by
-- scripts/ops/restore.ts — a backup that has never been restored is not a
-- verified backup).
CREATE TABLE backup_records (
    id text PRIMARY KEY,
    label text NOT NULL,
    file_path text NOT NULL,
    sha256 text NOT NULL,
    size_bytes bigint NOT NULL,
    migrations_applied integer NOT NULL,
    restore_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_backup_records_created ON backup_records (created_at DESC);
