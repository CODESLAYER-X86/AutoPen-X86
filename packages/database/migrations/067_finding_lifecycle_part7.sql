-- Part 7 §4-§6 — Finding lifecycle. The Part 6 state set is extended with the
-- full Part 7 pipeline: CANDIDATE -> UNDER_REVIEW -> VERIFICATION_PENDING ->
-- VERIFYING -> VERIFIED, honest alternatives (INCONCLUSIVE / REJECTED /
-- DUPLICATE) and the human terminal state ACCEPTED. Rejected findings are
-- never deleted: they are false-positive evaluation data (§4).
ALTER TABLE findings DROP CONSTRAINT findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (
    status IN (
        'PROPOSED', 'CONFIRMED', 'REJECTED', 'CANDIDATE', 'UNDER_REVIEW',
        'VERIFICATION_PENDING', 'VERIFYING', 'VERIFIED', 'INCONCLUSIVE',
        'DUPLICATE', 'ACCEPTED'
    )
);

-- Part 7 §38 — per-finding retest state (NOT_RETESTED / OPEN / FIXED /
-- PARTIALLY_FIXED / STILL_PRESENT).
ALTER TABLE findings
    ADD COLUMN retest_state text NOT NULL DEFAULT 'NOT_RETESTED',
    ADD CONSTRAINT findings_retest_state_check CHECK (
        retest_state IN ('NOT_RETESTED', 'OPEN', 'FIXED', 'PARTIALLY_FIXED', 'STILL_PRESENT')
    );

-- Part 7 §18-§19 — CVSS representation and deduplication linkage. CVSS stays
-- separate from confidence and business priority (§18); a high CVSS score
-- does not prove the vulnerability exists. duplicate_of marks correlated
-- findings; affected endpoint refs accumulate across merged duplicates (§20).
ALTER TABLE findings
    ADD COLUMN cvss_version text,
    ADD COLUMN cvss_vector text,
    ADD COLUMN cvss_base_score double precision,
    ADD COLUMN cvss_temporal_score double precision,
    ADD COLUMN cvss_environmental_score double precision,
    ADD COLUMN cvss_base_severity text,
    ADD COLUMN severity_source text NOT NULL DEFAULT 'CVSS_CALCULATOR',
    ADD COLUMN dedup_key text,
    ADD COLUMN duplicate_of text REFERENCES findings (id),
    ADD COLUMN observed_behavior text,
    ADD COLUMN expected_behavior text,
    ADD CONSTRAINT findings_cvss_version_check CHECK (cvss_version IS NULL OR cvss_version IN ('3.0', '3.1')),
    ADD CONSTRAINT findings_severity_source_check CHECK (severity_source IN ('CVSS_CALCULATOR', 'HUMAN_OVERRIDE')),
    ADD CONSTRAINT findings_cvss_base_range CHECK (cvss_base_score IS NULL OR (cvss_base_score >= 0 AND cvss_base_score <= 10)),
    ADD CONSTRAINT findings_cvss_base_severity_check CHECK (
        cvss_base_severity IS NULL OR cvss_base_severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    );

CREATE INDEX idx_findings_dedup ON findings (engagement_id, dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX idx_findings_duplicates ON findings (duplicate_of) WHERE duplicate_of IS NOT NULL;

-- Part 7 §5, §67 — auditable lifecycle transitions (engine AND human). The
-- agent's original conclusion is never silently overwritten (§67).
CREATE TABLE finding_lifecycle_events (
    id text PRIMARY KEY,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    from_status text NOT NULL,
    to_status text NOT NULL,
    reason text NOT NULL,
    actor text NOT NULL DEFAULT 'ENGINE',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT finding_lifecycle_actor_check CHECK (actor IN ('ENGINE', 'HUMAN'))
);

CREATE INDEX idx_finding_lifecycle ON finding_lifecycle_events (finding_id, created_at);
CREATE INDEX idx_finding_lifecycle_engagement ON finding_lifecycle_events (engagement_id, created_at DESC);

-- Part 7 §70 — evidence quality levels. Not all evidence is equally
-- authoritative: RAW -> EXTRACTED -> CORRELATED -> ANALYZED -> VERIFIED.
CREATE TABLE finding_evidence_quality (
    id text PRIMARY KEY,
    finding_id text NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    evidence_id text NOT NULL REFERENCES evidence (id) ON DELETE CASCADE,
    quality text NOT NULL,
    note text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT evidence_quality_check CHECK (quality IN ('RAW', 'EXTRACTED', 'CORRELATED', 'ANALYZED', 'VERIFIED')),
    CONSTRAINT finding_evidence_unique UNIQUE (finding_id, evidence_id)
);

CREATE INDEX idx_feq_engagement ON finding_evidence_quality (engagement_id);
