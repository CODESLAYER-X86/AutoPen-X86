-- Part 3 — WebSocket observation (spec §36).
CREATE TABLE websocket_connections (
    id text PRIMARY KEY,
    engagement_id text NOT NULL REFERENCES engagements (id) ON DELETE CASCADE,
    context_id text NOT NULL,
    page_id text,
    url text NOT NULL,
    origin text,
    opened_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz,
    close_code integer
);

CREATE INDEX idx_websocket_connections_engagement ON websocket_connections (engagement_id);

CREATE TABLE websocket_messages (
    id text PRIMARY KEY,
    connection_id text NOT NULL REFERENCES websocket_connections (id) ON DELETE CASCADE,
    direction text NOT NULL,
    is_binary boolean NOT NULL DEFAULT false,
    payload_artifact_ref text,
    payload_preview text,
    byte_size integer NOT NULL DEFAULT 0,
    truncated boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT websocket_messages_direction_check CHECK (direction IN ('CLIENT_TO_SERVER','SERVER_TO_CLIENT'))
);

CREATE INDEX idx_websocket_messages_connection ON websocket_messages (connection_id, created_at);
