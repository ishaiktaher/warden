-- PostgreSQL migration for Warden credential connections and layered policies.
-- Apply under an owner role, then run the service with a non-bypass-RLS role.

ALTER TABLE connectors ADD COLUMN IF NOT EXISTS credential_mode TEXT NOT NULL DEFAULT 'bearer';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS credential_config TEXT NOT NULL DEFAULT '{}';
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS grant_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS layer TEXT NOT NULL DEFAULT 'platform';
ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS target_id TEXT NOT NULL DEFAULT '*';

CREATE TABLE IF NOT EXISTS oauth_providers (
  provider_id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
  client_secret_alias TEXT NOT NULL, authorization_url TEXT NOT NULL,
  token_url TEXT NOT NULL, api_base_url TEXT NOT NULL,
  default_scopes TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  tenant_id TEXT NOT NULL DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system')
);
CREATE TABLE IF NOT EXISTS credential_connections (
  connection_id TEXT PRIMARY KEY, provider_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL, account_identifier TEXT NOT NULL,
  credential_alias TEXT NOT NULL, credential_kind TEXT NOT NULL,
  granted_scopes TEXT NOT NULL, access_expires_at TEXT,
  refresh_expires_at TEXT, status TEXT NOT NULL, metadata TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_used_at TEXT,
  tenant_id TEXT NOT NULL DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system')
);
CREATE TABLE IF NOT EXISTS credential_grants (
  grant_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES credential_connections(connection_id),
  principal_type TEXT NOT NULL, principal_id TEXT NOT NULL, label TEXT NOT NULL,
  scopes TEXT NOT NULL, allowed_methods TEXT NOT NULL,
  path_patterns TEXT NOT NULL, expires_at TEXT, status TEXT NOT NULL,
  reason TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  last_used_at TEXT,
  tenant_id TEXT NOT NULL DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system'),
  UNIQUE(connection_id, principal_type, principal_id, label)
);
CREATE TABLE IF NOT EXISTS grant_delegations (
  delegation_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES credential_grants(grant_id),
  agent_id TEXT NOT NULL REFERENCES agents(agent_id), status TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT,
  tenant_id TEXT NOT NULL DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system'),
  UNIQUE(grant_id, agent_id)
);
CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES oauth_providers(provider_id),
  principal_id TEXT NOT NULL, agent_id TEXT, label TEXT NOT NULL,
  provider_scopes TEXT NOT NULL, grant_scopes TEXT NOT NULL,
  allowed_methods TEXT NOT NULL, path_patterns TEXT NOT NULL,
  grant_expires_at TEXT, reason TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  consumed_at TEXT,
  tenant_id TEXT NOT NULL DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system')
);

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'oauth_providers','credential_connections','credential_grants','grant_delegations'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
      table_name
    );
  END LOOP;
END $$;

-- OAuth state is a global, random-hash callback index. Application code reads
-- only its tenant_id, then restores tenant scope before any connection write.
ALTER TABLE oauth_states DISABLE ROW LEVEL SECURITY;
