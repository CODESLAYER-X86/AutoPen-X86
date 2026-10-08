-- Test registry (spec Part 2 §28-§29): persistent record of every meaningful
-- test with a deterministic fingerprint used for duplicate detection.
CREATE TABLE tests (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    task_id text REFERENCES tasks (id) ON DELETE SET NULL,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    test_type text NOT NULL,
    target text NOT NULL DEFAULT '',
    identity text,
    mutation_summary text,
    fingerprint text NOT NULL,
    status text NOT NULL DEFAULT 'PENDING',
    result_summary text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tests_status_check CHECK (
        status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'DUPLICATE')
    ),
    CONSTRAINT tests_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_tests_engagement ON tests (engagement_id, created_at DESC);
CREATE INDEX idx_tests_task ON tests (task_id);
CREATE INDEX idx_tests_fingerprint ON tests (engagement_id, fingerprint);
