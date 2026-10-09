-- Part 7 §25-§34, §63-§66 — Reports. A report is a STRUCTURED artifact with
-- claim-to-evidence mapping (§34), a cryptographic integrity manifest (§66)
-- and a validation gate (§65): reports with unsupported claims, unredacted
-- secrets or nonexistent evidence references are REJECTED before export.
-- Rendered artifacts live in object storage; `content` holds the normalized
-- structure every exporter (JSON / HTML / Markdown / PDF) renders from.
CREATE TABLE reports (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    type text NOT NULL,
    status text NOT NULL DEFAULT 'GENERATING',
    version integer NOT NULL DEFAULT 1,
    title text NOT NULL,
    manifest jsonb,
    claims jsonb NOT NULL DEFAULT '[]'::jsonb,
    validation_issues jsonb NOT NULL DEFAULT '[]'::jsonb,
    content jsonb NOT NULL DEFAULT '{}'::jsonb,
    redactions jsonb NOT NULL DEFAULT '[]'::jsonb,
    generated_by text NOT NULL,
    generated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT report_type_check CHECK (type IN ('EXECUTIVE', 'TECHNICAL', 'MACHINE', 'RETEST', 'CTF_SOLUTION')),
    CONSTRAINT report_status_check CHECK (status IN ('GENERATING', 'VALIDATED', 'REJECTED', 'EXPORTED'))
);

CREATE INDEX idx_reports_engagement ON reports (engagement_id, generated_at DESC);
CREATE UNIQUE INDEX idx_reports_engagement_version ON reports (engagement_id, type, version);

-- §63 — rendered export artifacts (one row per format), content-addressed
-- via SHA-256 for integrity verification.
CREATE TABLE report_exports (
    id text PRIMARY KEY,
    report_id text NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    format text NOT NULL,
    byte_size integer NOT NULL,
    sha256 char(64) NOT NULL,
    content_reference text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT report_export_format_check CHECK (format IN ('JSON', 'HTML', 'MARKDOWN', 'PDF'))
);

CREATE INDEX idx_report_exports_report ON report_exports (report_id, created_at DESC);
CREATE INDEX idx_report_exports_engagement ON report_exports (engagement_id, created_at DESC);
