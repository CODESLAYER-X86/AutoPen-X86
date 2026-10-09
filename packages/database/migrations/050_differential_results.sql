-- Part 4 — Differential comparison results (spec §25-§28, §61).
-- Semantic (structural) comparisons, not byte-only: schema changes, field
-- diffs, volatile-field marking and deterministic similarity scores.
CREATE TABLE differential_results (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    test_id text,
    hypothesis_id text,
    baseline_request_id text,
    candidate_request_id text,
    baseline_identity text,
    candidate_identity text,
    summary jsonb NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_differentials_engagement ON differential_results (engagement_id, created_at DESC);
CREATE INDEX idx_differentials_hypothesis ON differential_results (hypothesis_id);
CREATE INDEX idx_differentials_baseline ON differential_results (baseline_request_id);
