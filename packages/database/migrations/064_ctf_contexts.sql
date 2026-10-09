-- Part 6 §4/§29-§31: CTF challenge context. One row per CTF engagement.
-- The challenge description/title/hints are UNTRUSTED challenge data: they are
-- stored here, rendered to models only inside untrusted delimiters.
CREATE TABLE ctf_contexts (
    engagement_id text PRIMARY KEY REFERENCES engagements (id) ON DELETE CASCADE,
    id text NOT NULL UNIQUE,
    title text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    hints jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Operator-declared flag format, e.g. "flag{...}" (regex body).
    flag_format text,
    status text NOT NULL DEFAULT 'UNSOLVED',
    flag_value text,
    flag_evidence_id text,
    solved_at timestamptz,
    -- Deterministic riddle-analysis output (§29): interpretations per clue.
    analysis jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ctf_status_check CHECK (status IN ('UNSOLVED', 'PARTIAL', 'SOLVED'))
);

-- Part 6 §29: individual clues extracted from title/description/hints/artifacts.
CREATE TABLE ctf_clues (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    source text NOT NULL,
    text_content text NOT NULL,
    -- Deterministic interpretations: [{concept, confidence}] (§29 example).
    interpretations jsonb NOT NULL DEFAULT '[]'::jsonb,
    branch_id text REFERENCES reasoning_branches (id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'NEW',
    dead_end_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ctf_clue_source_check CHECK (
        source IN ('TITLE', 'DESCRIPTION', 'HINT', 'ARTIFACT', 'OBSERVATION', 'USER')
    ),
    CONSTRAINT ctf_clue_status_check CHECK (
        status IN ('NEW', 'ANALYZED', 'INTERPRETED', 'CONSUMED', 'DEAD_END')
    )
);

CREATE INDEX idx_ctf_clues_engagement ON ctf_clues (engagement_id, status);

-- Part 6 §31: flag-condition hypotheses. A challenge may only become SOLVED
-- when evidence exists that the success condition was satisfied.
CREATE TABLE flag_conditions (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    hypothesis_id text REFERENCES hypotheses (id) ON DELETE SET NULL,
    condition_description text NOT NULL,
    pattern text,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence_kinds jsonb NOT NULL DEFAULT '[]'::jsonb,
    detected_value text,
    status text NOT NULL DEFAULT 'HYPOTHESIZED',
    detected_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT flag_condition_status_check CHECK (
        status IN ('HYPOTHESIZED', 'SUPPORTED', 'DETECTED', 'REFUTED')
    )
);

CREATE INDEX idx_flag_conditions_engagement ON flag_conditions (engagement_id, status);
