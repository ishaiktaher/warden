"""SQLite persistence for the local control-plane implementation."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import re
from pathlib import Path
import sqlite3
from typing import Iterator

from .config import Settings


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner TEXT NOT NULL,
  purpose TEXT NOT NULL,
  model_provider TEXT NOT NULL,
  agent_version TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  environment TEXT NOT NULL,
  risk_tier TEXT NOT NULL,
  allowed_tools TEXT NOT NULL,
  allowed_actions TEXT NOT NULL,
  allowed_data_classifications TEXT NOT NULL,
  max_delegation_depth INTEGER NOT NULL,
  approved_parents TEXT NOT NULL,
  approved_children TEXT NOT NULL,
  expires_at TEXT,
  review_date TEXT,
  status TEXT NOT NULL,
  approved_by TEXT,
  owner_signature TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS owners (
  owner_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  roles TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_versions (
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  agent_version TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(agent_id, agent_version)
);

CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  runtime_secret_hash TEXT,
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  task TEXT NOT NULL,
  parent_run_id TEXT REFERENCES runs(run_id),
  environment TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  ended_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  parent_task_id TEXT REFERENCES tasks(task_id),
  description TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS tool_calls (
  tool_call_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  connector_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  algorithm TEXT NOT NULL,
  public_pem TEXT NOT NULL,
  private_pem TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retired_at TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
  jti TEXT PRIMARY KEY,
  kid TEXT NOT NULL REFERENCES signing_keys(kid),
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  principal_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  resources TEXT NOT NULL,
  delegation_depth INTEGER NOT NULL,
  parent_jti TEXT REFERENCES tokens(jti),
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS delegations (
  delegation_id TEXT PRIMARY KEY,
  parent_jti TEXT NOT NULL REFERENCES tokens(jti),
  child_jti TEXT NOT NULL REFERENCES tokens(jti),
  parent_agent_id TEXT NOT NULL,
  child_agent_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS connectors (
  connector_id TEXT PRIMARY KEY,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  adapter_type TEXT NOT NULL,
  endpoint TEXT,
  http_method TEXT,
  resource_patterns TEXT NOT NULL,
  required_scopes TEXT NOT NULL,
  secret_alias TEXT,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  risk_tier TEXT NOT NULL,
  rate_limit_per_minute INTEGER NOT NULL,
  credential_mode TEXT NOT NULL DEFAULT 'bearer',
  credential_config TEXT NOT NULL DEFAULT '{}',
  grant_required INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_providers (
  provider_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  client_secret_alias TEXT NOT NULL,
  authorization_url TEXT NOT NULL,
  token_url TEXT NOT NULL,
  api_base_url TEXT NOT NULL,
  default_scopes TEXT NOT NULL,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credential_connections (
  connection_id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  owner_principal_id TEXT NOT NULL,
  account_identifier TEXT NOT NULL,
  credential_alias TEXT NOT NULL,
  credential_kind TEXT NOT NULL,
  granted_scopes TEXT NOT NULL,
  access_expires_at TEXT,
  refresh_expires_at TEXT,
  status TEXT NOT NULL,
  metadata TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS credential_grants (
  grant_id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES credential_connections(connection_id),
  principal_type TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  label TEXT NOT NULL,
  scopes TEXT NOT NULL,
  allowed_methods TEXT NOT NULL,
  path_patterns TEXT NOT NULL,
  expires_at TEXT,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_used_at TEXT,
  UNIQUE(connection_id, principal_type, principal_id, label)
);

CREATE TABLE IF NOT EXISTS grant_delegations (
  delegation_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL REFERENCES credential_grants(grant_id),
  agent_id TEXT NOT NULL REFERENCES agents(agent_id),
  status TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  UNIQUE(grant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS oauth_states (
  state_hash TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL REFERENCES oauth_providers(provider_id),
  principal_id TEXT NOT NULL,
  agent_id TEXT,
  label TEXT NOT NULL,
  provider_scopes TEXT NOT NULL,
  grant_scopes TEXT NOT NULL,
  allowed_methods TEXT NOT NULL,
  path_patterns TEXT NOT NULL,
  grant_expires_at TEXT,
  reason TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS secret_aliases (
  alias TEXT PRIMARY KEY,
  encrypted_value TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  agent_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  resolved_by TEXT,
  resolved_at TEXT,
  expires_at TEXT,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS policy_bundles (
  policy_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  name TEXT NOT NULL,
  layer TEXT NOT NULL DEFAULT 'platform',
  target_id TEXT NOT NULL DEFAULT '*',
  rules TEXT NOT NULL,
  status TEXT NOT NULL,
  owner TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_at TEXT,
  PRIMARY KEY(policy_id, version)
);

CREATE TABLE IF NOT EXISTS revocations (
  revocation_id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  revoked_by TEXT NOT NULL,
  revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  principal_id TEXT,
  agent_id TEXT,
  run_id TEXT,
  task_id TEXT,
  tool_call_id TEXT,
  decision TEXT,
  payload TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  event_hash TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS action_requests (
  request_id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL,
  token_jti TEXT NOT NULL,
  requested_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS request_nonces (
  token_jti TEXT NOT NULL,
  nonce TEXT NOT NULL,
  used_at TEXT NOT NULL,
  PRIMARY KEY(token_jti, nonce)
);

CREATE TABLE IF NOT EXISTS execution_requests (
  token_jti TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  response_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(token_jti, idempotency_key)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crm_cases (
  case_id TEXT PRIMARY KEY,
  customer TEXT NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL,
  priority TEXT NOT NULL,
  latest_update TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_drafts (
  draft_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jira_tickets (
  ticket_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_reviews (
  review_id TEXT PRIMARY KEY,
  repository TEXT NOT NULL,
  reference TEXT NOT NULL,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS emulator_resources (
  resource TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
            if "runtime_secret_hash" not in columns:
                connection.execute("ALTER TABLE runs ADD COLUMN runtime_secret_hash TEXT")
            connector_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(connectors)")
            }
            for name, definition in (
                ("credential_mode", "TEXT NOT NULL DEFAULT 'bearer'"),
                ("credential_config", "TEXT NOT NULL DEFAULT '{}'"),
                ("grant_required", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in connector_columns:
                    connection.execute(f"ALTER TABLE connectors ADD COLUMN {name} {definition}")
            policy_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(policy_bundles)")
            }
            if "layer" not in policy_columns:
                connection.execute(
                    "ALTER TABLE policy_bundles ADD COLUMN layer TEXT NOT NULL DEFAULT 'platform'"
                )
            if "target_id" not in policy_columns:
                connection.execute(
                    "ALTER TABLE policy_bundles ADD COLUMN target_id TEXT NOT NULL DEFAULT '*'"
                )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def one(self, sql: str, parameters: tuple = ()) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(sql, parameters).fetchone()

    def all(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return list(connection.execute(sql, parameters).fetchall())

    def execute(self, sql: str, parameters: tuple = ()) -> None:
        with self.connect() as connection:
            connection.execute(sql, parameters)

    @contextmanager
    def tenant_scope(self, tenant_id: str):
        del tenant_id
        yield

    def current_tenant(self) -> str:
        return "default"

    def namespace(self, value: str) -> str:
        return value


class _PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _sql(sql: str) -> str:
        if sql.strip().upper() in {"BEGIN", "BEGIN IMMEDIATE"}:
            return "SELECT 1"
        return re.sub(r"\?", "%s", sql)

    def execute(self, sql: str, parameters: tuple = ()):
        return self.connection.execute(self._sql(sql), parameters)


class PostgresDatabase:
    """Pooled PostgreSQL adapter used by production deployments."""

    def __init__(self, database_url: str, *, migrate: bool = False):
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise RuntimeError("PostgreSQL dependencies are not installed") from exc
        self._dict_row = dict_row
        self._tenant: ContextVar[str] = ContextVar("warden_tenant", default="system")
        self.pool = ConnectionPool(
            conninfo=database_url.replace("postgresql+psycopg://", "postgresql://"),
            min_size=1, max_size=20, timeout=10, open=True,
            kwargs={"row_factory": dict_row},
        )
        self.pool.wait(timeout=10)
        if migrate:
            self._initialize()
        else:
            self._verify_schema()

    def _initialize(self) -> None:
        schema = SCHEMA.replace("PRAGMA journal_mode=WAL;", "").replace(
            "PRAGMA foreign_keys=ON;", ""
        ).replace(
            "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
        )
        with self.connect() as connection:
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext('warden-schema-migrations'))"
            )
            for statement in schema.split(";"):
                if statement.strip():
                    connection.execute(statement)
            tenant_tables = (
                "agents", "owners", "agent_versions", "runs", "tasks", "tool_calls",
                "tokens", "delegations", "connectors", "secret_aliases",
                "oauth_providers", "credential_connections", "credential_grants",
                "grant_delegations", "oauth_states",
                "approvals", "policy_bundles", "revocations", "audit_events",
                "action_requests", "request_nonces", "execution_requests", "settings",
                "crm_cases", "email_drafts", "jira_tickets", "github_reviews",
                "emulator_resources",
            )
            for table in tenant_tables:
                connection.execute(
                    f"""ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL
                    DEFAULT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'system')"""
                )
                connection.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                connection.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                connection.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
                connection.execute(
                    f"""CREATE POLICY tenant_isolation ON {table}
                    USING (tenant_id = current_setting('app.tenant_id', true))
                    WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"""
                )
            for statement in (
                "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS credential_mode TEXT NOT NULL DEFAULT 'bearer'",
                "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS credential_config TEXT NOT NULL DEFAULT '{}'",
                "ALTER TABLE connectors ADD COLUMN IF NOT EXISTS grant_required INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS layer TEXT NOT NULL DEFAULT 'platform'",
                "ALTER TABLE policy_bundles ADD COLUMN IF NOT EXISTS target_id TEXT NOT NULL DEFAULT '*'",
            ):
                connection.execute(statement)
            # Public verification keys are shared infrastructure metadata. They
            # contain no private material and must be visible for every tenant's
            # capability verification and the public key endpoint.
            connection.execute("ALTER TABLE signing_keys DISABLE ROW LEVEL SECURITY")
            connection.execute("DROP POLICY IF EXISTS tenant_isolation ON signing_keys")
            # OAuth callbacks arrive before an application identity exists. The
            # random state hash is the lookup key; the callback then restores
            # the originating tenant scope before writing any tenant data.
            connection.execute("ALTER TABLE oauth_states DISABLE ROW LEVEL SECURITY")
            connection.execute("DROP POLICY IF EXISTS tenant_isolation ON oauth_states")

    def _verify_schema(self) -> None:
        required_tables = {
            "agents", "runs", "tasks", "tokens", "connectors",
            "credential_connections", "credential_grants", "policy_bundles",
            "audit_events", "execution_requests",
        }
        required_columns = {
            ("connectors", "grant_required"),
            ("connectors", "credential_mode"),
            ("policy_bundles", "layer"),
            ("policy_bundles", "target_id"),
        }
        with self.connect() as connection:
            existing_tables = {
                row["table_name"] for row in connection.execute(
                    """SELECT table_name FROM information_schema.tables
                    WHERE table_schema='public'"""
                ).fetchall()
            }
            missing_tables = required_tables - existing_tables
            existing_columns = {
                (row["table_name"], row["column_name"])
                for row in connection.execute(
                    """SELECT table_name,column_name FROM information_schema.columns
                    WHERE table_schema='public'"""
                ).fetchall()
            }
            missing_columns = required_columns - existing_columns
        if missing_tables or missing_columns:
            details = sorted(missing_tables) + [
                f"{table}.{column}" for table, column in sorted(missing_columns)
            ]
            raise RuntimeError(
                "Production database schema is not current; run "
                f"python -m scripts.migrate ({', '.join(details)})"
            )

    @contextmanager
    def connect(self):
        with self.pool.connection() as raw:
            try:
                raw.execute(
                    "SELECT set_config('app.tenant_id', %s, true)",
                    (self._tenant.get(),),
                )
                yield _PostgresConnection(raw)
                raw.commit()
            except Exception:
                raw.rollback()
                raise

    def one(self, sql: str, parameters: tuple = ()):
        with self.connect() as connection:
            return connection.execute(sql, parameters).fetchone()

    def all(self, sql: str, parameters: tuple = ()) -> list:
        with self.connect() as connection:
            return list(connection.execute(sql, parameters).fetchall())

    def execute(self, sql: str, parameters: tuple = ()) -> None:
        with self.connect() as connection:
            connection.execute(sql, parameters)

    @contextmanager
    def tenant_scope(self, tenant_id: str):
        if not tenant_id or len(tenant_id) > 200:
            raise ValueError("Tenant identity is invalid")
        token = self._tenant.set(tenant_id)
        try:
            yield
        finally:
            self._tenant.reset(token)

    def current_tenant(self) -> str:
        return self._tenant.get()

    def namespace(self, value: str) -> str:
        return f"{self.current_tenant()}::{value}"


def create_database(settings: Settings):
    if settings.production:
        if not settings.database_url:
            raise RuntimeError("Production PostgreSQL DATABASE_URL is required")
        return PostgresDatabase(settings.database_url, migrate=settings.auto_migrate)
    return Database(settings.database_path)
