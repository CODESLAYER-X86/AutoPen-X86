-- Part 3 — pages opened inside a browser context (spec §3, §74).
CREATE TABLE browser_pages (
    id text PRIMARY KEY,
    context_id text NOT NULL REFERENCES browser_contexts (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz
);

CREATE INDEX idx_browser_pages_context ON browser_pages (context_id);
