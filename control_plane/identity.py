"""Minimum viable per-app OIDC identity and immediate deprovisioning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import base64
from typing import Any
from uuid import uuid4

import jwt
import requests

from .audit import AuditLedger
from .config import Settings
from .connect_sessions import ConnectSessionService
from .database import Database
from .errors import WardenAPIError
from .secrets import SecretsBroker


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AppIdentityService:
    def __init__(
        self,
        database: Database,
        settings: Settings,
        secrets_broker: SecretsBroker,
        connect_sessions: ConnectSessionService,
        audit: AuditLedger,
    ):
        self.database, self.settings, self.secrets = database, settings, secrets_broker
        self.connect_sessions, self.audit = connect_sessions, audit

    def create_app(self, app_id: str, name: str, owner: str) -> dict[str, Any]:
        try:
            self.database.execute(
                "INSERT INTO apps(app_id,name,owner,created_at) VALUES(?,?,?,?)",
                (app_id, name, owner, _now().isoformat()),
            )
        except Exception as exc:
            raise WardenAPIError("conflict", "App already exists") from exc
        self.audit.append("app.created", owner, payload={"app_id": app_id})
        return {"app_id": app_id, "name": name, "owner": owner}

    def apps(self, owner: str) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT app_id,name,owner,created_at FROM apps WHERE owner=? ORDER BY created_at",
            (owner,),
        )
        return [dict(row) for row in rows]

    def identity_config(self, app_id: str, owner: str) -> dict[str, Any]:
        self._owned_app(app_id, owner)
        row = self.database.one(
            """SELECT app_id,issuer,client_id,user_id_claim,email_claim,groups_claim,created_at
            FROM app_identity_providers WHERE app_id=?""",
            (app_id,),
        )
        if not row:
            raise WardenAPIError("not_found", "App identity provider was not found")
        return dict(row)

    def users(self, app_id: str, owner: str) -> list[dict[str, Any]]:
        self._owned_app(app_id, owner)
        rows = self.database.all(
            "SELECT * FROM app_users WHERE app_id=? ORDER BY created_at", (app_id,)
        )
        return [
            {
                **{key: row[key] for key in row.keys() if key != "groups_json"},
                "groups": json.loads(row["groups_json"]),
            }
            for row in rows
        ]

    def begin_browser_login(
        self, app_id: str, redirect_path: str = "/portal"
    ) -> dict[str, str]:
        provider = self.database.one(
            "SELECT * FROM app_identity_providers WHERE app_id=?", (app_id,)
        )
        if not provider:
            raise WardenAPIError("not_found", "App identity provider was not found")
        try:
            discovery = requests.get(
                f"{provider['issuer']}/.well-known/openid-configuration", timeout=5
            )
            discovery.raise_for_status()
            authorization_endpoint = discovery.json()["authorization_endpoint"]
        except Exception as exc:
            raise WardenAPIError("unavailable", "OIDC discovery failed") from exc
        state, verifier, nonce = (
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(64),
            secrets.token_urlsafe(24),
        )
        alias = f"browser-pkce-{hashlib.sha256(state.encode()).hexdigest()}"
        self.secrets.store(alias, verifier, "browser-oidc", "oidc-pkce")
        now = _now()
        self.database.execute(
            """INSERT INTO browser_oidc_states(state_hash,app_id,tenant_context,verifier_encrypted,nonce,
            redirect_path,status,created_at,expires_at) VALUES(?,?,?,?,?,?,'pending',?,?)""",
            (
                hashlib.sha256(state.encode()).hexdigest(),
                app_id,
                self.database.current_tenant(),
                alias,
                nonce,
                redirect_path if redirect_path.startswith("/") else "/portal",
                now.isoformat(),
                (now + timedelta(minutes=10)).isoformat(),
            ),
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        from urllib.parse import urlencode

        return {
            "state": state,
            "authorization_url": authorization_endpoint
            + "?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": provider["client_id"],
                    "redirect_uri": f"{self.settings.public_url}/portal/auth/callback",
                    "scope": "openid email profile",
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            ),
        }

    def browser_state_tenant(self, state: str) -> str:
        row = self.database.one(
            "SELECT tenant_context FROM browser_oidc_states WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),),
        )
        if not row:
            raise WardenAPIError("unauthorized", "OIDC state is invalid")
        return row["tenant_context"]

    def complete_browser_login(
        self, state: str, state_cookie: str | None, code: str
    ) -> dict[str, Any]:
        digest = hashlib.sha256(state.encode()).hexdigest()
        if not state_cookie or not hmac.compare_digest(digest, state_cookie):
            raise WardenAPIError("unauthorized", "OIDC state cookie is invalid")
        row = self.database.one(
            "SELECT * FROM browser_oidc_states WHERE state_hash=?", (digest,)
        )
        if not row or row["status"] != "pending":
            raise WardenAPIError(
                "unauthorized", "OIDC state is invalid or already used"
            )
        if datetime.fromisoformat(row["expires_at"]) <= _now():
            raise WardenAPIError("expired_session", "OIDC state has expired")
        with self.database.connect() as connection:
            claimed = connection.execute(
                "UPDATE browser_oidc_states SET status='used' WHERE state_hash=? AND status='pending'",
                (digest,),
            )
            if claimed.rowcount != 1:
                raise WardenAPIError(
                    "unauthorized", "OIDC state is invalid or already used"
                )
        provider = self.database.one(
            "SELECT * FROM app_identity_providers WHERE app_id=?", (row["app_id"],)
        )
        if not provider:
            raise WardenAPIError("not_found", "App identity provider was not found")
        verifier = self.secrets.resolve_internal(
            row["verifier_encrypted"], purpose="oidc-pkce"
        )
        client_secret = self.secrets.resolve_internal(
            provider["client_secret_alias"], purpose="oidc-client"
        )
        try:
            discovery = requests.get(
                f"{provider['issuer']}/.well-known/openid-configuration", timeout=5
            )
            discovery.raise_for_status()
            token = requests.post(
                discovery.json()["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"{self.settings.public_url}/portal/auth/callback",
                    "client_id": provider["client_id"],
                    "client_secret": client_secret,
                    "code_verifier": verifier,
                },
                timeout=10,
            )
            token.raise_for_status()
            id_token = token.json()["id_token"]
        except Exception as exc:
            raise WardenAPIError("unavailable", "OIDC code exchange failed") from exc
        resolved = self.resolve(row["app_id"], id_token, expected_nonce=row["nonce"])
        csrf = secrets.token_urlsafe(32)
        self.database.execute(
            "UPDATE user_sessions SET csrf_hash=? WHERE token_hash=?",
            (
                hashlib.sha256(csrf.encode()).hexdigest(),
                hashlib.sha256(resolved["session_token"].encode()).hexdigest(),
            ),
        )
        return {**resolved, "csrf_token": csrf, "redirect_path": row["redirect_path"]}

    def authenticate_session(self, token: str) -> dict[str, Any]:
        if not token.startswith("wus_"):
            raise WardenAPIError("unauthorized", "Warden user session is invalid")
        row = self.database.one(
            """SELECT s.*,u.email,u.groups_json,u.status AS user_status,a.owner
            FROM user_sessions s JOIN app_users u ON u.user_id=s.user_id
            JOIN apps a ON a.app_id=s.app_id WHERE s.token_hash=?""",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )
        if not row:
            raise WardenAPIError("unauthorized", "Warden user session is invalid")
        if row["status"] == "revoked" or row["user_status"] != "active":
            raise WardenAPIError("revoked", "Warden user session has been revoked")
        if datetime.fromisoformat(row["expires_at"]) <= _now():
            raise WardenAPIError("expired_session", "Warden user session has expired")
        return {
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "app_id": row["app_id"],
            "email": row["email"],
            "groups": json.loads(row["groups_json"]),
            "owner": row["owner"],
            "csrf_hash": row["csrf_hash"],
        }

    def session_tenant(self, token: str) -> str:
        row = self.database.one(
            "SELECT tenant_context FROM user_session_tenants WHERE token_hash=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        )
        if not row:
            raise WardenAPIError("unauthorized", "Warden user session is invalid")
        return row["tenant_context"]

    def validate_csrf(self, session: dict[str, Any], supplied: str | None) -> None:
        expected = session.get("csrf_hash")
        actual = hashlib.sha256((supplied or "").encode()).hexdigest()
        if not expected or not hmac.compare_digest(expected, actual):
            raise WardenAPIError("forbidden", "CSRF token is invalid")

    def logout(self, token: str) -> None:
        self.database.execute(
            "UPDATE user_sessions SET status='revoked',revoked_at=? WHERE token_hash=?",
            (_now().isoformat(), hashlib.sha256(token.encode()).hexdigest()),
        )

    def _owned_app(self, app_id: str, owner: str) -> None:
        if not self.database.one(
            "SELECT app_id FROM apps WHERE app_id=? AND owner=?", (app_id, owner)
        ):
            raise WardenAPIError("not_found", "App was not found")

    def configure(
        self, app_id: str, config: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        if self.database.one(
            "SELECT app_id FROM app_identity_providers WHERE app_id=?", (app_id,)
        ):
            raise WardenAPIError(
                "conflict", "An app can register exactly one identity provider"
            )
        if not self.database.one("SELECT app_id FROM apps WHERE app_id=?", (app_id,)):
            raise WardenAPIError("not_found", "App was not found")
        issuer = config["issuer"].rstrip("/")
        if not issuer.startswith("https://") and not (
            not self.settings.production and issuer.startswith("http://localhost")
        ):
            raise WardenAPIError("invalid_request", "OIDC issuer must use HTTPS")
        webhook_secret = "whsec_" + secrets.token_urlsafe(32)
        alias = f"idp-webhook-{app_id}"
        self.secrets.store(alias, webhook_secret, actor, "idp-webhook")
        self.database.execute(
            """INSERT INTO app_identity_providers(app_id,issuer,client_id,client_secret_alias,
            user_id_claim,email_claim,groups_claim,webhook_secret_hash,created_at)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                app_id,
                issuer,
                config["client_id"],
                config["client_secret_alias"],
                config["user_id_claim"],
                config["email_claim"],
                config["groups_claim"],
                alias,
                _now().isoformat(),
            ),
        )
        self.audit.append(
            "identity_provider.configured",
            actor,
            payload={"app_id": app_id, "issuer": issuer},
        )
        return {
            "app_id": app_id,
            "issuer": issuer,
            "webhook_secret": webhook_secret,
            "webhook_path": f"/apps/{app_id}/identity/webhook",
        }

    def resolve(
        self, app_id: str, id_token: str, expected_nonce: str | None = None
    ) -> dict[str, Any]:
        provider = self.database.one(
            "SELECT * FROM app_identity_providers WHERE app_id=?", (app_id,)
        )
        if not provider:
            raise WardenAPIError("not_found", "App identity provider was not found")
        claims = self._verify(provider, id_token)
        if expected_nonce and not hmac.compare_digest(
            str(claims.get("nonce", "")), expected_nonce
        ):
            raise WardenAPIError("unauthorized", "Identity token nonce is invalid")
        subject = self._claim(claims, provider["user_id_claim"])
        if not isinstance(subject, str) or not subject:
            raise WardenAPIError(
                "unauthorized", "Identity token lacks the configured user ID claim"
            )
        email, groups = (
            self._claim(claims, provider["email_claim"]),
            self._claim(claims, provider["groups_claim"]) or [],
        )
        groups = [groups] if isinstance(groups, str) else groups
        if not isinstance(groups, list) or not all(
            isinstance(item, str) for item in groups
        ):
            raise WardenAPIError(
                "unauthorized", "Identity token groups claim is invalid"
            )
        existing = self.database.one(
            "SELECT * FROM app_users WHERE app_id=? AND external_subject_id=?",
            (app_id, subject),
        )
        if existing and existing["status"] == "deprovisioned":
            raise WardenAPIError("revoked", "User has been deprovisioned")
        now, user_id = _now(), existing["user_id"] if existing else str(uuid4())
        self.database.execute(
            """INSERT INTO app_users(user_id,app_id,external_subject_id,email,groups_json,status,created_at,updated_at)
            VALUES(?,?,?,?,?,'active',?,?) ON CONFLICT(app_id,external_subject_id) DO UPDATE SET
            email=excluded.email,groups_json=excluded.groups_json,updated_at=excluded.updated_at""",
            (
                user_id,
                app_id,
                subject,
                email if isinstance(email, str) else None,
                json.dumps(groups),
                now.isoformat(),
                now.isoformat(),
            ),
        )
        session_id, session_token, expires = (
            str(uuid4()),
            "wus_" + secrets.token_urlsafe(32),
            now + timedelta(hours=8),
        )
        self.database.execute(
            "INSERT INTO user_sessions(session_id,token_hash,app_id,user_id,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
            (
                session_id,
                hashlib.sha256(session_token.encode()).hexdigest(),
                app_id,
                user_id,
                "active",
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        self.database.execute(
            "INSERT INTO user_session_tenants(token_hash,tenant_context) VALUES(?,?)",
            (
                hashlib.sha256(session_token.encode()).hexdigest(),
                self.database.current_tenant(),
            ),
        )
        self.audit.append(
            "identity.resolved",
            user_id,
            principal_id=user_id,
            payload={"app_id": app_id, "jit_provisioned": existing is None},
        )
        return {
            "user": {
                "user_id": user_id,
                "app_id": app_id,
                "external_subject_id": subject,
                "email": email,
                "groups": groups,
                "status": "active",
            },
            "session_token": session_token,
            "expires_at": expires.isoformat(),
        }

    def deprovision(
        self, app_id: str, raw_body: bytes, signature: str | None
    ) -> dict[str, Any]:
        provider = self.database.one(
            "SELECT * FROM app_identity_providers WHERE app_id=?", (app_id,)
        )
        if not provider:
            raise WardenAPIError("not_found", "App identity provider was not found")
        secret = self.secrets.resolve_internal(
            provider["webhook_secret_hash"], purpose="idp-webhook"
        )
        expected = (
            "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        )
        if not signature or not hmac.compare_digest(signature, expected):
            raise WardenAPIError("unauthorized", "Webhook signature is invalid")
        try:
            event = json.loads(raw_body)
            if event.get("event_type") != "user.deprovisioned":
                raise ValueError
            subject = event["external_subject_id"]
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            raise WardenAPIError("invalid_request", "Webhook event is invalid") from exc
        user = self.database.one(
            "SELECT * FROM app_users WHERE app_id=? AND external_subject_id=?",
            (app_id, subject),
        )
        if not user:
            raise WardenAPIError("not_found", "User was not found")
        now = _now().isoformat()
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE app_users SET status='deprovisioned',updated_at=? WHERE user_id=?",
                (now, user["user_id"]),
            )
            grants = connection.execute(
                "UPDATE credential_grants SET status='revoked',updated_at=? WHERE principal_id=? AND status='active'",
                (now, user["user_id"]),
            ).rowcount
            sessions = connection.execute(
                "UPDATE user_sessions SET status='revoked',revoked_at=? WHERE user_id=? AND status='active'",
                (now, user["user_id"]),
            ).rowcount
        connect_sessions = self.connect_sessions.revoke_for_principal(user["user_id"])
        self.audit.append(
            "identity.deprovisioned",
            "idp-webhook",
            principal_id=user["user_id"],
            decision="revoke",
            payload={
                "app_id": app_id,
                "grants_revoked": grants,
                "sessions_revoked": sessions + connect_sessions,
                "event_id": event.get("event_id"),
            },
        )
        return {
            "status": "deprovisioned",
            "user_id": user["user_id"],
            "grants_revoked": grants,
            "sessions_revoked": sessions + connect_sessions,
        }

    @staticmethod
    def _claim(claims: dict[str, Any], path: str) -> Any:
        value: Any = claims
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return value

    @staticmethod
    def _verify(provider: Any, token: str) -> dict[str, Any]:
        try:
            discovery = requests.get(
                f"{provider['issuer']}/.well-known/openid-configuration", timeout=5
            )
            discovery.raise_for_status()
            key = jwt.PyJWKClient(
                discovery.json()["jwks_uri"]
            ).get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=provider["client_id"],
                issuer=provider["issuer"],
                options={"require": ["exp", "sub"]},
            )
        except Exception as exc:
            raise WardenAPIError(
                "unauthorized", "Identity token verification failed"
            ) from exc
