"""Credential connections, independently revocable grants, and GitHub OAuth."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fnmatch
import hashlib
import json
import secrets
import threading
from typing import Any, Iterator, cast
from urllib.parse import urlencode, urlparse
from uuid import uuid4

import requests

from .audit import AuditLedger
from .config import Settings
from .secrets import SecretsBroker


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class CredentialError(RuntimeError):
    pass


class CredentialService:
    """Keeps credential custody separate from request capabilities.

    A capability authorizes an action at a point in time. A grant authorizes a
    principal or delegated agent to exercise a specific stored connection. Both
    must independently allow before a credential is resolved.
    """

    _locks_guard = threading.Lock()
    _locks: dict[str, threading.Lock] = {}

    def __init__(
        self, database: Any, secrets_broker: SecretsBroker,
        audit: AuditLedger, settings: Settings,
    ) -> None:
        self.database = database
        self.secrets = secrets_broker
        self.audit = audit
        self.settings = settings
        self.redis = None
        if settings.production:
            try:
                import redis

                self.redis = redis.Redis.from_url(
                    cast(str, settings.redis_url), socket_connect_timeout=3,
                    socket_timeout=3, decode_responses=True,
                )
                self.redis.ping()
            except Exception as exc:
                raise RuntimeError("Production credential refresh locking is unavailable") from exc

    def register_github_provider(
        self, *, client_id: str, client_secret_alias: str,
        default_scopes: list[str], owner: str,
    ) -> dict[str, Any]:
        secret = self.database.one(
            "SELECT status FROM secret_aliases WHERE alias=?",
            (self.database.namespace(client_secret_alias),),
        )
        if not secret or secret["status"] != "active":
            raise CredentialError("GitHub client secret alias is unavailable")
        now = _iso()
        provider_key = self.database.namespace("github")
        self.database.execute(
            """INSERT INTO oauth_providers(
            provider_id,client_id,client_secret_alias,authorization_url,token_url,
            api_base_url,default_scopes,status,owner,created_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(provider_id) DO UPDATE SET client_id=excluded.client_id,
            client_secret_alias=excluded.client_secret_alias,
            default_scopes=excluded.default_scopes,status='active',owner=excluded.owner,
            updated_at=excluded.updated_at""",
            (provider_key, client_id, client_secret_alias,
             "https://github.com/login/oauth/authorize",
             "https://github.com/login/oauth/access_token",
             "https://api.github.com", _json(sorted(set(default_scopes))),
             "active", owner, now, now),
        )
        self.audit.append("oauth_provider.configured", owner, payload={
            "provider_id": "github", "default_scopes": sorted(set(default_scopes)),
        })
        return self.provider("github")

    def provider(self, provider_id: str) -> dict[str, Any]:
        provider_key = self.database.namespace(provider_id)
        row = self.database.one(
            "SELECT * FROM oauth_providers WHERE provider_id=?", (provider_key,)
        )
        if not row:
            raise CredentialError("Unknown credential provider")
        result = dict(row)
        result["provider_id"] = provider_id
        result["default_scopes"] = json.loads(result["default_scopes"])
        result.pop("client_secret_alias", None)
        return result

    def start_github_connect(
        self, *, principal_id: str, agent_id: str | None, label: str,
        provider_scopes: list[str], grant_scopes: list[str],
        allowed_methods: list[str], path_patterns: list[str],
        ttl_seconds: int | None, reason: str,
    ) -> dict[str, Any]:
        provider_key = self.database.namespace("github")
        provider = self.database.one(
            "SELECT * FROM oauth_providers WHERE provider_id=? AND status='active'",
            (provider_key,),
        )
        if not provider:
            raise CredentialError("GitHub OAuth provider is not configured")
        if agent_id:
            agent = self.database.one(
                "SELECT status,allowed_actions FROM agents WHERE agent_id=?", (agent_id,)
            )
            if not agent or agent["status"] != "active":
                raise CredentialError("Delegated agent is not active")
            if not set(grant_scopes).issubset(set(json.loads(agent["allowed_actions"]))):
                raise CredentialError("Credential grant scopes exceed the agent manifest")
        defaults = set(json.loads(provider["default_scopes"]))
        requested_provider_scopes = set(provider_scopes or defaults)
        if not requested_provider_scopes.issubset(defaults):
            raise CredentialError("Requested OAuth scopes exceed provider configuration")
        methods = self._methods(allowed_methods)
        paths = self._paths(path_patterns)
        if not grant_scopes:
            raise CredentialError("At least one Warden grant scope is required")
        raw_state = secrets.token_urlsafe(32)
        state_hash = hashlib.sha256(raw_state.encode()).hexdigest()
        redirect_uri = f"{self.settings.public_url}/oauth/github/callback"
        now = _now()
        grant_expires_at = (
            now + timedelta(seconds=ttl_seconds) if ttl_seconds else None
        )
        self.database.execute(
            """INSERT INTO oauth_states(
            state_hash,provider_id,principal_id,agent_id,label,provider_scopes,
            grant_scopes,allowed_methods,path_patterns,grant_expires_at,reason,
            redirect_uri,status,created_at,expires_at,consumed_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (state_hash, provider_key, principal_id, agent_id, label,
             _json(sorted(requested_provider_scopes)), _json(sorted(set(grant_scopes))),
             _json(methods), _json(paths), _iso(grant_expires_at) if grant_expires_at else None,
             reason, redirect_uri, "pending", _iso(now),
             _iso(now + timedelta(minutes=10))),
        )
        query = urlencode({
            "client_id": provider["client_id"], "redirect_uri": redirect_uri,
            "scope": " ".join(sorted(requested_provider_scopes)), "state": raw_state,
        })
        self.audit.append(
            "oauth.connect_started", principal_id, principal_id=principal_id,
            agent_id=agent_id, payload={
                "provider_id": "github", "grant_scopes": sorted(set(grant_scopes)),
                "provider_scopes": sorted(requested_provider_scopes), "label": label,
            },
        )
        return {
            "provider_id": "github",
            "connect_url": f"{provider['authorization_url']}?{query}",
            "expires_at": _iso(now + timedelta(minutes=10)),
        }

    def complete_github_connect(self, *, code: str, state: str) -> dict[str, Any]:
        state_row = self._consume_state(state)
        provider = self.database.one(
            "SELECT * FROM oauth_providers WHERE provider_id=? AND status='active'",
            (state_row["provider_id"],),
        )
        if not provider:
            raise CredentialError("GitHub OAuth provider is unavailable")
        client_secret = self.secrets.resolve_for_connector(
            provider["client_secret_alias"], connector_id="oauth-github",
            run_id="oauth-connect", task_id="oauth-connect", tool_call_id=str(uuid4()),
        )
        try:
            token_response = requests.post(
                provider["token_url"],
                headers={"Accept": "application/json"},
                data={
                    "client_id": provider["client_id"],
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": state_row["redirect_uri"],
                },
                timeout=15, allow_redirects=False,
            )
            token_response.raise_for_status()
            token = token_response.json()
            if not isinstance(token, dict) or not isinstance(token.get("access_token"), str):
                raise CredentialError("GitHub token exchange omitted an access token")
            identity_response = requests.get(
                provider["api_base_url"].rstrip("/") + "/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token['access_token']}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=15, allow_redirects=False,
            )
            identity_response.raise_for_status()
            identity = identity_response.json()
            if not isinstance(identity, dict) or not identity.get("id") or not identity.get("login"):
                raise CredentialError("GitHub identity response is invalid")
        except CredentialError:
            self._fail_state(state_row["state_hash"])
            raise
        except (requests.RequestException, ValueError) as exc:
            self._fail_state(state_row["state_hash"])
            raise CredentialError("GitHub OAuth exchange failed") from exc

        now = _now()
        access_expires = self._expiry(now, token.get("expires_in"))
        refresh_expires = self._expiry(now, token.get("refresh_token_expires_in"))
        credential = {
            "type": "oauth", "access_token": token["access_token"],
            "token_type": token.get("token_type", "bearer"),
            "refresh_token": token.get("refresh_token"),
            "access_expires_at": _iso(access_expires) if access_expires else None,
            "refresh_expires_at": _iso(refresh_expires) if refresh_expires else None,
        }
        connection_id = str(uuid4())
        credential_alias = f"connections/{connection_id}"
        self.secrets.store(credential_alias, _json(credential), "oauth-github")
        self.database.execute(
            """INSERT INTO credential_connections(
            connection_id,provider_id,owner_principal_id,account_identifier,
            credential_alias,credential_kind,granted_scopes,access_expires_at,
            refresh_expires_at,status,metadata,created_at,updated_at,last_used_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (connection_id, state_row["provider_id"], state_row["principal_id"], str(identity["login"]),
             credential_alias, "oauth", _json(sorted({
                 scope.strip() for scope in token.get("scope", "").split(",")
                 if scope.strip()
             })),
             _iso(access_expires) if access_expires else None,
             _iso(refresh_expires) if refresh_expires else None, "active",
             _json({"provider_user_id": str(identity["id"]), "login": identity["login"]}),
             _iso(now), _iso(now)),
        )
        grant = self._create_grant(
            connection_id=connection_id, principal_type="user",
            principal_id=state_row["principal_id"], label=state_row["label"],
            scopes=json.loads(state_row["grant_scopes"]),
            allowed_methods=json.loads(state_row["allowed_methods"]),
            path_patterns=json.loads(state_row["path_patterns"]),
            expires_at=state_row["grant_expires_at"], reason=state_row["reason"],
        )
        if state_row["agent_id"]:
            self.delegate_grant(
                grant["grant_id"], state_row["agent_id"],
                state_row["principal_id"], state_row["reason"],
            )
        self.audit.append(
            "oauth.connected", state_row["principal_id"],
            principal_id=state_row["principal_id"], agent_id=state_row["agent_id"],
            payload={
                "provider_id": "github", "connection_id": connection_id,
                "grant_id": grant["grant_id"], "account_identifier": identity["login"],
            },
        )
        self.database.execute(
            "UPDATE oauth_states SET status='completed' WHERE state_hash=?",
            (state_row["state_hash"],),
        )
        return {"status": "connected", "connection": self.connection(connection_id),
                "grant": grant}

    def create_managed_connection(
        self, *, provider_id: str, owner_principal_id: str,
        account_identifier: str, credential: dict[str, Any],
        principal_type: str, principal_id: str, label: str,
        grant_scopes: list[str], allowed_methods: list[str],
        path_patterns: list[str], ttl_seconds: int | None, reason: str,
        actor: str,
    ) -> dict[str, Any]:
        if not credential or not all(isinstance(key, str) for key in credential):
            raise CredentialError("Managed credential is invalid")
        connection_id = str(uuid4())
        alias = f"connections/{connection_id}"
        self.secrets.store(alias, _json({"type": "managed", **credential}), actor)
        now = _now()
        self.database.execute(
            """INSERT INTO credential_connections(
            connection_id,provider_id,owner_principal_id,account_identifier,
            credential_alias,credential_kind,granted_scopes,access_expires_at,
            refresh_expires_at,status,metadata,created_at,updated_at,last_used_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (connection_id, provider_id, owner_principal_id, account_identifier,
             alias, "managed", _json([]), None, None, "active", _json({}),
             _iso(now), _iso(now)),
        )
        expires_at = _iso(now + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
        grant = self._create_grant(
            connection_id=connection_id, principal_type=principal_type,
            principal_id=principal_id, label=label, scopes=grant_scopes,
            allowed_methods=self._methods(allowed_methods),
            path_patterns=self._paths(path_patterns), expires_at=expires_at,
            reason=reason,
        )
        self.audit.append("connection.created", actor, principal_id=owner_principal_id,
                          payload={"connection_id": connection_id, "provider_id": provider_id,
                                   "credential_kind": "managed", "grant_id": grant["grant_id"]})
        return {"connection": self.connection(connection_id), "grant": grant}

    def authorize_grant(
        self, grant_id: str, *, principal_id: str, agent_id: str,
        action: str, method: str, endpoint: str,
    ) -> dict[str, Any]:
        row = self.database.one(
            """SELECT g.*,c.provider_id,c.credential_alias,c.credential_kind,
            c.owner_principal_id,c.status AS connection_status,c.access_expires_at
            FROM credential_grants g JOIN credential_connections c
            ON c.connection_id=g.connection_id WHERE g.grant_id=?""",
            (grant_id,),
        )
        if not row or row["status"] != "active" or row["connection_status"] != "active":
            raise CredentialError("Credential grant is unavailable")
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= _now():
            raise CredentialError("Credential grant has expired")
        delegated = self.database.one(
            """SELECT delegation_id FROM grant_delegations
            WHERE grant_id=? AND agent_id=? AND status='active'""",
            (grant_id, agent_id),
        )
        direct_agent = row["principal_type"] == "agent" and row["principal_id"] == agent_id
        principal_matches = row["owner_principal_id"] == principal_id
        if not principal_matches:
            raise CredentialError("Credential grant owner does not match the capability principal")
        if not (delegated or direct_agent):
            raise CredentialError("Credential grant is not delegated to this agent")
        scopes = set(json.loads(row["scopes"]))
        if action not in scopes:
            raise CredentialError("Action is outside credential grant scope")
        methods = set(json.loads(row["allowed_methods"]))
        if methods and method.upper() not in methods:
            raise CredentialError("HTTP method is outside credential grant restrictions")
        path = urlparse(endpoint).path or "/"
        patterns = json.loads(row["path_patterns"])
        if patterns and not any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
            raise CredentialError("Endpoint path is outside credential grant restrictions")
        result = dict(row)
        for field in ("scopes", "allowed_methods", "path_patterns"):
            result[field] = json.loads(result[field])
        return result

    def resolve_credential(
        self, grant: dict[str, Any], *, run_id: str, task_id: str,
        tool_call_id: str, connector_id: str,
    ) -> dict[str, Any]:
        credential = self._read_credential(
            grant["credential_alias"], run_id, task_id, tool_call_id, connector_id
        )
        if grant["credential_kind"] == "oauth":
            credential = self._refresh_if_needed(grant, credential, run_id, task_id,
                                                  tool_call_id, connector_id)
        now = _iso()
        self.database.execute(
            "UPDATE credential_grants SET last_used_at=?,updated_at=? WHERE grant_id=?",
            (now, now, grant["grant_id"]),
        )
        self.database.execute(
            "UPDATE credential_connections SET last_used_at=?,updated_at=? WHERE connection_id=?",
            (now, now, grant["connection_id"]),
        )
        self.audit.append(
            "credential.exercised", "credential-broker", principal_id=grant["owner_principal_id"],
            run_id=run_id, task_id=task_id, tool_call_id=tool_call_id,
            payload={"grant_id": grant["grant_id"], "connection_id": grant["connection_id"],
                     "provider_id": grant["provider_id"], "connector_id": connector_id},
        )
        return credential

    def delegate_grant(self, grant_id: str, agent_id: str, actor: str, reason: str) -> dict[str, Any]:
        grant = self.database.one(
            """SELECT g.*,c.owner_principal_id FROM credential_grants g
            JOIN credential_connections c ON c.connection_id=g.connection_id
            WHERE g.grant_id=? AND g.status='active'""", (grant_id,),
        )
        agent = self.database.one(
            "SELECT status,allowed_actions FROM agents WHERE agent_id=?", (agent_id,)
        )
        if not grant or not agent or agent["status"] != "active":
            raise CredentialError("Grant or delegated agent is unavailable")
        if not set(json.loads(grant["scopes"])).issubset(
            set(json.loads(agent["allowed_actions"]))
        ):
            raise CredentialError("Credential grant scopes exceed the agent manifest")
        if actor != grant["owner_principal_id"] and actor != "control-plane-admin":
            raise CredentialError("Only the connection owner may delegate this grant")
        delegation_id = str(uuid4())
        now = _iso()
        self.database.execute(
            """INSERT INTO grant_delegations(
            delegation_id,grant_id,agent_id,status,created_by,created_at,revoked_at
            ) VALUES(?,?,?,?,?,?,NULL)
            ON CONFLICT(grant_id,agent_id) DO UPDATE SET status='active',
            created_by=excluded.created_by,created_at=excluded.created_at,revoked_at=NULL""",
            (delegation_id, grant_id, agent_id, "active", actor, now),
        )
        self.audit.append("grant.delegated", actor, principal_id=grant["owner_principal_id"],
                          agent_id=agent_id, payload={"grant_id": grant_id, "reason": reason})
        row = self.database.one(
            "SELECT * FROM grant_delegations WHERE grant_id=? AND agent_id=?",
            (grant_id, agent_id),
        )
        return dict(row)

    def revoke_grant(self, grant_id: str, actor: str, reason: str) -> None:
        row = self.database.one(
            """SELECT g.status,c.owner_principal_id FROM credential_grants g
            JOIN credential_connections c ON c.connection_id=g.connection_id
            WHERE g.grant_id=?""", (grant_id,),
        )
        if not row:
            raise CredentialError("Unknown credential grant")
        if actor != row["owner_principal_id"] and actor != "control-plane-admin":
            raise CredentialError("Only the connection owner may revoke this grant")
        self.database.execute(
            "UPDATE credential_grants SET status='revoked',reason=?,updated_at=? WHERE grant_id=?",
            (reason, _iso(), grant_id),
        )
        self.database.execute(
            "UPDATE grant_delegations SET status='revoked',revoked_at=? WHERE grant_id=?",
            (_iso(), grant_id),
        )
        self.audit.append("grant.revoked", actor, payload={"grant_id": grant_id, "reason": reason})

    def revoke_connection(self, connection_id: str, actor: str, reason: str) -> None:
        row = self.database.one(
            "SELECT * FROM credential_connections WHERE connection_id=?", (connection_id,)
        )
        if not row:
            raise CredentialError("Unknown credential connection")
        if actor != row["owner_principal_id"] and actor != "control-plane-admin":
            raise CredentialError("Only the connection owner may revoke this connection")
        if row["status"] == "revoked":
            return
        if row["credential_kind"] == "oauth" and str(row["provider_id"]).endswith("github"):
            self._revoke_github_token(dict(row), actor)
        self.database.execute(
            "UPDATE credential_connections SET status='revoked',updated_at=? WHERE connection_id=?",
            (_iso(), connection_id),
        )
        self.database.execute(
            "UPDATE credential_grants SET status='revoked',reason=?,updated_at=? WHERE connection_id=?",
            (reason, _iso(), connection_id),
        )
        self.secrets.revoke(row["credential_alias"], actor)
        self.audit.append("connection.revoked", actor, principal_id=row["owner_principal_id"],
                          payload={"connection_id": connection_id, "reason": reason})

    def _revoke_github_token(self, connection: dict[str, Any], actor: str) -> None:
        provider = self.database.one(
            "SELECT * FROM oauth_providers WHERE provider_id=? AND status='active'",
            (connection["provider_id"],),
        )
        if not provider:
            raise CredentialError("GitHub OAuth provider is unavailable for revocation")
        credential = self._read_credential(
            connection["credential_alias"], "connection-revoke", "connection-revoke",
            str(uuid4()), "oauth-github-revoke",
        )
        access_token = credential.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise CredentialError("GitHub credential cannot be revoked at the provider")
        client_secret = self.secrets.resolve_for_connector(
            provider["client_secret_alias"], connector_id="oauth-github-revoke",
            run_id="connection-revoke", task_id="connection-revoke",
            tool_call_id=str(uuid4()),
        )
        endpoint = (
            provider["api_base_url"].rstrip("/")
            + f"/applications/{provider['client_id']}/token"
        )
        try:
            response = requests.delete(
                endpoint,
                auth=(provider["client_id"], client_secret),
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={"access_token": access_token},
                timeout=15,
                allow_redirects=False,
            )
            if response.status_code not in {204, 404}:
                response.raise_for_status()
        except requests.RequestException as exc:
            raise CredentialError("GitHub rejected provider-side token revocation") from exc
        self.audit.append(
            "credential.provider_revoked", actor,
            principal_id=connection["owner_principal_id"],
            payload={
                "connection_id": connection["connection_id"],
                "provider_id": "github", "provider_status": response.status_code,
            },
        )

    def connection(self, connection_id: str) -> dict[str, Any]:
        row = self.database.one(
            "SELECT * FROM credential_connections WHERE connection_id=?", (connection_id,)
        )
        if not row:
            raise CredentialError("Unknown credential connection")
        result = dict(row)
        result["granted_scopes"] = json.loads(result["granted_scopes"])
        result["metadata"] = json.loads(result["metadata"])
        result.pop("credential_alias", None)
        return result

    def grant(self, grant_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM credential_grants WHERE grant_id=?", (grant_id,))
        if not row:
            raise CredentialError("Unknown credential grant")
        result = dict(row)
        for field in ("scopes", "allowed_methods", "path_patterns"):
            result[field] = json.loads(result[field])
        return result

    def connections_for(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self.database.all(
            """SELECT connection_id FROM credential_connections
            WHERE owner_principal_id=? ORDER BY created_at DESC""", (principal_id,),
        )
        return [self.connection(row["connection_id"]) for row in rows]

    def grants_for(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self.database.all(
            """SELECT g.grant_id FROM credential_grants g JOIN credential_connections c
            ON c.connection_id=g.connection_id WHERE c.owner_principal_id=?
            ORDER BY g.created_at DESC""", (principal_id,),
        )
        return [self.grant(row["grant_id"]) for row in rows]

    def _create_grant(
        self, *, connection_id: str, principal_type: str, principal_id: str,
        label: str, scopes: list[str], allowed_methods: list[str],
        path_patterns: list[str], expires_at: str | None, reason: str,
    ) -> dict[str, Any]:
        if principal_type not in {"user", "group", "system", "agent"}:
            raise CredentialError("Invalid grant principal type")
        if not scopes:
            raise CredentialError("Credential grant requires at least one scope")
        grant_id = str(uuid4())
        now = _iso()
        try:
            self.database.execute(
                """INSERT INTO credential_grants(
                grant_id,connection_id,principal_type,principal_id,label,scopes,
                allowed_methods,path_patterns,expires_at,status,reason,created_at,
                updated_at,last_used_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
                (grant_id, connection_id, principal_type, principal_id, label,
                 _json(sorted(set(scopes))), _json(self._methods(allowed_methods)),
                 _json(self._paths(path_patterns)), expires_at, "active", reason, now, now),
            )
        except Exception as exc:
            raise CredentialError("Credential grant could not be created") from exc
        self.audit.append("grant.created", principal_id, principal_id=principal_id,
                          payload={"grant_id": grant_id, "connection_id": connection_id,
                                   "scopes": sorted(set(scopes)), "label": label})
        return self.grant(grant_id)

    def _consume_state(self, raw_state: str) -> dict[str, Any]:
        state_hash = hashlib.sha256(raw_state.encode()).hexdigest()
        with self.database.connect() as connection:
            updated = connection.execute(
                """UPDATE oauth_states SET status='exchanging',consumed_at=?
                WHERE state_hash=? AND status='pending' AND expires_at>?
                RETURNING *""", (_iso(), state_hash, _iso()),
            )
            row = updated.fetchone()
            if not row:
                raise CredentialError("OAuth state is invalid or already consumed")
        return dict(row)

    def oauth_state_tenant(self, raw_state: str) -> str:
        """Resolve only the callback tenant; possession of state remains required."""
        if not self.settings.production:
            return self.database.current_tenant()
        state_hash = hashlib.sha256(raw_state.encode()).hexdigest()
        row = self.database.one(
            "SELECT tenant_id FROM oauth_states WHERE state_hash=?", (state_hash,)
        )
        if not row:
            raise CredentialError("OAuth state is invalid or already consumed")
        return str(row["tenant_id"])

    def _fail_state(self, state_hash: str) -> None:
        self.database.execute(
            "UPDATE oauth_states SET status='failed' WHERE state_hash=?", (state_hash,)
        )

    def _read_credential(
        self, alias: str, run_id: str, task_id: str,
        tool_call_id: str, connector_id: str,
    ) -> dict[str, Any]:
        try:
            raw = self.secrets.resolve_for_connector(
                alias, connector_id=connector_id, run_id=run_id,
                task_id=task_id, tool_call_id=tool_call_id,
            )
        except RuntimeError as exc:
            raise CredentialError("Stored credential is unavailable") from exc
        try:
            credential = json.loads(raw)
        except ValueError as exc:
            raise CredentialError("Stored credential format is invalid") from exc
        if not isinstance(credential, dict):
            raise CredentialError("Stored credential format is invalid")
        return credential

    def _refresh_if_needed(
        self, grant: dict[str, Any], credential: dict[str, Any],
        run_id: str, task_id: str, tool_call_id: str, connector_id: str,
    ) -> dict[str, Any]:
        expiry = credential.get("access_expires_at")
        if not expiry or datetime.fromisoformat(expiry) > _now() + timedelta(seconds=60):
            return credential
        if not credential.get("refresh_token"):
            raise CredentialError("OAuth access token expired and cannot be refreshed")
        with self._refresh_lock(grant["connection_id"]):
            current = self._read_credential(
                grant["credential_alias"], run_id, task_id, tool_call_id, connector_id
            )
            current_expiry = current.get("access_expires_at")
            if current_expiry and datetime.fromisoformat(current_expiry) > _now() + timedelta(seconds=60):
                return current
            provider = self.database.one(
                "SELECT * FROM oauth_providers WHERE provider_id=? AND status='active'",
                (grant["provider_id"],),
            )
            if not provider or not (
                provider["provider_id"] == "github"
                or str(provider["provider_id"]).endswith("::github")
            ):
                raise CredentialError("OAuth refresh provider is unavailable")
            client_secret = self.secrets.resolve_for_connector(
                provider["client_secret_alias"], connector_id="oauth-refresh",
                run_id=run_id, task_id=task_id, tool_call_id=tool_call_id,
            )
            try:
                response = requests.post(
                    provider["token_url"], headers={"Accept": "application/json"},
                    data={
                        "client_id": provider["client_id"],
                        "client_secret": client_secret,
                        "grant_type": "refresh_token",
                        "refresh_token": current["refresh_token"],
                    },
                    timeout=15, allow_redirects=False,
                )
                response.raise_for_status()
                refreshed = response.json()
                if not isinstance(refreshed, dict) or not refreshed.get("access_token"):
                    raise CredentialError("OAuth refresh response is invalid")
            except CredentialError:
                raise
            except (requests.RequestException, ValueError) as exc:
                raise CredentialError("OAuth token refresh failed") from exc
            now = _now()
            access_expires = self._expiry(now, refreshed.get("expires_in"))
            refresh_expires = self._expiry(
                now, refreshed.get("refresh_token_expires_in")
            )
            next_credential = {
                **current,
                "access_token": refreshed["access_token"],
                "refresh_token": refreshed.get("refresh_token", current["refresh_token"]),
                "token_type": refreshed.get("token_type", current.get("token_type", "bearer")),
                "access_expires_at": (
                    _iso(access_expires) if access_expires
                    else current.get("access_expires_at")
                ),
                "refresh_expires_at": (
                    _iso(refresh_expires) if refresh_expires
                    else current.get("refresh_expires_at")
                ),
            }
            self.secrets.store(grant["credential_alias"], _json(next_credential), "oauth-refresh")
            self.database.execute(
                """UPDATE credential_connections SET access_expires_at=?,refresh_expires_at=?,
                updated_at=? WHERE connection_id=?""",
                (next_credential["access_expires_at"], next_credential["refresh_expires_at"],
                 _iso(), grant["connection_id"]),
            )
            self.audit.append("credential.refreshed", "credential-broker",
                              payload={"connection_id": grant["connection_id"],
                                       "provider_id": grant["provider_id"]})
            return next_credential

    @contextmanager
    def _refresh_lock(self, connection_id: str) -> Iterator[None]:
        if self.redis:
            lock = self.redis.lock(
                f"warden:credential-refresh:{connection_id}", timeout=30,
                blocking_timeout=5,
            )
            if not lock.acquire(blocking=True):
                raise CredentialError("Credential refresh is already in progress")
            try:
                yield
            finally:
                lock.release()
            return
        with self._locks_guard:
            lock = self._locks.setdefault(connection_id, threading.Lock())
        if not lock.acquire(timeout=5):
            raise CredentialError("Credential refresh is already in progress")
        try:
            yield
        finally:
            lock.release()

    @staticmethod
    def _methods(methods: list[str]) -> list[str]:
        allowed = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
        normalized = sorted({method.upper() for method in methods})
        if any(method not in allowed for method in normalized):
            raise CredentialError("Grant contains an unsupported HTTP method")
        return normalized

    @staticmethod
    def _paths(patterns: list[str]) -> list[str]:
        normalized = sorted(set(patterns or ["/*"]))
        if any(not pattern.startswith("/") or ".." in pattern for pattern in normalized):
            raise CredentialError("Grant endpoint path pattern is invalid")
        return normalized

    @staticmethod
    def _expiry(now: datetime, seconds: Any) -> datetime | None:
        if seconds is None:
            return None
        try:
            value = int(seconds)
        except (TypeError, ValueError) as exc:
            raise CredentialError("OAuth expiry is invalid") from exc
        if value <= 0:
            raise CredentialError("OAuth expiry is invalid")
        return now + timedelta(seconds=value)
