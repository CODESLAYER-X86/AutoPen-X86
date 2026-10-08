-- Hypothesis evidence links (spec Part 2 §24): auditable reasoning graph
-- connecting hypotheses to observations, tests, and evidence.
CREATE TABLE hypothesis_links (
    id text PRIMARY KEY,
    hypothesis_id text NOT NULL REFERENCES hypotheses (id) ON DELETE CASCADE,
    ref_type text NOT NULL,
    ref_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT hypothesis_links_ref_type_check CHECK (
        ref_type IN ('OBSERVATION', 'TEST', 'EVIDENCE')
    ),
    CONSTRAINT hypothesis_links_unique UNIQUE (hypothesis_id, ref_type, ref_id)
);

CREATE INDEX idx_hypothesis_links_hypothesis ON hypothesis_links (hypothesis_id);
CREATE INDEX idx_hypothesis_links_ref ON hypothesis_links (ref_type, ref_id);
