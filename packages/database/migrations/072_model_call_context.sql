-- Part 7 §83 — model cost tracking. Every model invocation records its
-- prompt version and context size so exact quota analysis and prompt-version
-- evaluation (§56) are possible.
ALTER TABLE model_calls
    ADD COLUMN prompt_version text,
    ADD COLUMN context_size integer;

CREATE INDEX idx_model_calls_prompt_version ON model_calls (engagement_id, prompt_version);
