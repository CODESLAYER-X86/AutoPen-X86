-- Part 6 §6: autonomous engine state per engagement. The engine-level phase
-- machine sits ABOVE the Part 2 agent-run state machine. Phase is persisted
-- in the database — never process memory (§54 "never rely on process memory").
-- Optimistic concurrency via `version`; conditional transitions are guarded
-- WHERE clauses in the repository.
CREATE TABLE autonomous_engine_states (
    engagement_id text PRIMARY KEY REFERENCES engagements (id) ON DELETE CASCADE,
    id text NOT NULL UNIQUE,
    phase text NOT NULL DEFAULT 'CREATED',
    mode text NOT NULL DEFAULT 'PENTEST_MODE',
    -- Why the engine is currently waiting (WAITING_FOR_* phases).
    waiting_reason text,
    -- Strategy focus/summary snapshot for the current cycle (§45/§64).
    strategy_summary text,
    replan_count integer NOT NULL DEFAULT 0,
    cycle_count integer NOT NULL DEFAULT 0,
    last_replan_trigger text,
    -- Engine-scoped dedup counters (§40-§41 anti-loop).
    knowledge_query_repeats integer NOT NULL DEFAULT 0,
    -- Lease identity of the engine instance currently driving this engagement.
    engine_instance_id text,
    stop_reason text,
    started_at timestamptz,
    finished_at timestamptz,
    last_transition_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 0,
    CONSTRAINT autonomous_phase_check CHECK (
        phase IN ('CREATED', 'INITIALIZING', 'RECON', 'MODELING', 'HYPOTHESIS_GENERATION',
                  'TESTING', 'ANALYSIS', 'VERIFICATION', 'REPLANNING',
                  'COMPLETED', 'STOPPED', 'CANCELLED', 'FAILED',
                  'WAITING_FOR_USER', 'WAITING_FOR_RESOURCE', 'WAITING_FOR_IDENTITY', 'WAITING_FOR_QUOTA')
    ),
    CONSTRAINT autonomous_mode_check CHECK (
        mode IN ('RECON_MODE', 'PENTEST_MODE', 'CTF_MODE')
    )
);

CREATE INDEX idx_autonomous_phase ON autonomous_engine_states (phase);
