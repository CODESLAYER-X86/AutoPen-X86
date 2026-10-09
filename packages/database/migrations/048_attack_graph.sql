-- Part 4 — Attack-surface graph (spec §4-§6).
-- Persistent nodes and relationships (§5: PostgreSQL is sufficient; no graph
-- database added merely because the system has a graph). Stable identifiers
-- (§6) and fingerprint idempotency (§111).
CREATE TABLE attack_nodes (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    node_type text NOT NULL,
    external_ref text,
    fingerprint text NOT NULL,
    label text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    confidence numeric NOT NULL DEFAULT 0.9,
    first_seen timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    CONSTRAINT attack_nodes_type_check CHECK (node_type IN ('ENGAGEMENT','TARGET','HOST','PORT','APPLICATION','PAGE','ENDPOINT','PARAMETER','FORM','SCRIPT','API','WEBSOCKET','IDENTITY','SESSION','OBJECT','WORKFLOW','STATE','SOURCE_FILE','ARTIFACT','HYPOTHESIS','FINDING')),
    CONSTRAINT attack_nodes_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT attack_nodes_fingerprint_unique UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX idx_attack_nodes_engagement_type ON attack_nodes (engagement_id, node_type);
CREATE INDEX idx_attack_nodes_external ON attack_nodes (engagement_id, external_ref);

CREATE TABLE attack_edges (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    source_node_id text NOT NULL REFERENCES attack_nodes (id) ON DELETE CASCADE,
    target_node_id text NOT NULL REFERENCES attack_nodes (id) ON DELETE CASCADE,
    relation text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    confidence numeric NOT NULL DEFAULT 0.9,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT attack_edges_relation_check CHECK (relation IN ('contains','loads','calls','accepts','owns','accesses','belongs_to','transitions_to','concerns','supports','references','observes','establishes')),
    CONSTRAINT attack_edges_confidence_range CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT attack_edges_unique UNIQUE (engagement_id, source_node_id, target_node_id, relation),
    CONSTRAINT attack_edges_no_self CHECK (source_node_id <> target_node_id)
);

CREATE INDEX idx_attack_edges_source ON attack_edges (source_node_id);
CREATE INDEX idx_attack_edges_target ON attack_edges (target_node_id);
