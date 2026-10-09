-- Part 8 §7: PostgreSQL row-level security as defense in depth. Application
-- authorization remains mandatory; RLS exists so that even a query that
-- bypasses the repository layer cannot cross tenant boundaries.
--
-- The application connects as the database owner in development (embedded
-- cluster); table owners bypass RLS unless FORCE is used, so dev flows are
-- unaffected. Production deployments connect as aegis_app (see
-- docs/operations/deployment.md), which is subject to these policies.
--
-- Policy key: session GUC aegis.tenant_user_id, set per connection by the
-- application. Child tables resolve ownership through the SECURITY DEFINER
-- helper aegis.engagement_owner() to avoid policy recursion.

CREATE SCHEMA IF NOT EXISTS aegis;

CREATE OR REPLACE FUNCTION aegis.engagement_owner(engagement_id text)
RETURNS text
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT p.owner_id
      FROM projects p
      JOIN engagements e ON e.project_id = p.id
     WHERE e.id = engagement_id;
$$;

-- Non-login role for production application connections.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app NOLOGIN;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Enable RLS on tenant-owned tables.
-- ---------------------------------------------------------------------------

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_projects ON projects
    USING (owner_id = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (owner_id = current_setting('aegis.tenant_user_id', true));

ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_engagements ON engagements
    USING (aegis.engagement_owner(id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE api_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_api_credentials ON api_credentials
    USING (user_id = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (user_id = current_setting('aegis.tenant_user_id', true));

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_targets ON targets
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_evidence ON evidence
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_findings ON findings
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_reports ON reports
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE credential_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_credential_grants ON credential_grants
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

ALTER TABLE scope_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope_versions ON scope_versions
    USING (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true))
    WITH CHECK (aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true));

-- Security events: engagement-scoped rows are tenant-visible; platform-level
-- rows (engagement_id IS NULL) remain visible for incident monitoring.
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_security_events ON security_events
    USING (
        engagement_id IS NULL
        OR aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true)
    )
    WITH CHECK (
        engagement_id IS NULL
        OR aegis.engagement_owner(engagement_id) = current_setting('aegis.tenant_user_id', true)
    );

-- ---------------------------------------------------------------------------
-- Grants for the production application role.
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON projects, engagements, targets, evidence,
    findings, reports, api_credentials, credential_grants, scope_versions,
    security_events TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON users, auth_sessions, audit_log, scope,
    tasks, observations, outbox_events, circuit_breakers, incidents,
    retention_policies, backup_records, emergency_stop, events,
    identities, sessions, http_requests, http_responses, tool_executions,
    browser_contexts, downloads, dom_snapshots, websocket_connections TO aegis_app;
