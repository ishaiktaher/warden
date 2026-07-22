"""Backend-minted, signed, single-use Connect sessions."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, cast
from uuid import uuid4

from .audit import AuditLedger
from .config import Settings
from .database import Database
from .errors import WardenAPIError


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ConnectSessionService:
    def __init__(self, database: Database, settings: Settings, audit: AuditLedger):
        self.database = database
        self.audit = audit
        self._signing_key = hashlib.sha256(
            f"{settings.admin_key}:{settings.issuer}:connect-session".encode()
        ).digest()

    def mint(
        self,
        *,
        principal_id: str,
        allowed_providers: list[str],
        provider_scopes: list[str],
        grant_scopes: list[str],
        agent_id: str | None,
        allowed_methods: list[str],
        path_patterns: list[str],
        reason: str,
        label: str = "default",
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        if not allowed_providers or not grant_scopes:
            raise WardenAPIError(
                "invalid_scope", "Providers and grant scopes are required"
            )
        issued = _now()
        session_id = str(uuid4())
        payload = {
            "sid": session_id,
            "sub": principal_id,
            "agent_id": agent_id,
            "providers": sorted(set(allowed_providers)),
            "provider_scopes": sorted(set(provider_scopes)),
            "grant_scopes": sorted(set(grant_scopes)),
            "allowed_methods": sorted(
                set(method.upper() for method in allowed_methods)
            ),
            "path_patterns": path_patterns or ["/*"],
            "reason": reason,
            "label": label,
            "iat": int(issued.timestamp()),
            "exp": int((issued + timedelta(seconds=ttl_seconds)).timestamp()),
            "nonce": secrets.token_urlsafe(12),
        }
        encoded = _b64(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        signature = _b64(
            hmac.new(self._signing_key, encoded.encode(), hashlib.sha256).digest()
        )
        token = f"wcs_{encoded}.{signature}"
        self.database.execute(
            """INSERT INTO connect_sessions(
            session_id,token_hash,principal_id,agent_id,allowed_providers,provider_scopes,
            grant_scopes,allowed_methods,path_patterns,label,reason,status,created_at,expires_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                session_id,
                hashlib.sha256(token.encode()).hexdigest(),
                principal_id,
                agent_id,
                json.dumps(payload["providers"]),
                json.dumps(payload["provider_scopes"]),
                json.dumps(payload["grant_scopes"]),
                json.dumps(payload["allowed_methods"]),
                json.dumps(payload["path_patterns"]),
                label,
                reason,
                "active",
                issued.isoformat(),
                datetime.fromtimestamp(
                    cast(int, payload["exp"]), timezone.utc
                ).isoformat(),
            ),
        )
        self.audit.append(
            "connect_session.minted",
            principal_id,
            principal_id=principal_id,
            agent_id=agent_id,
            payload={
                "session_id": session_id,
                "allowed_providers": payload["providers"],
            },
        )
        return {
            "session_token": token,
            "expires_at": datetime.fromtimestamp(
                cast(int, payload["exp"]), timezone.utc
            ).isoformat(),
            "allowed_providers": payload["providers"],
        }

    def inspect(self, token: str) -> dict[str, Any]:
        payload = self._verify(token)
        row = self.database.one(
            "SELECT status FROM connect_sessions WHERE session_id=?", (payload["sid"],)
        )
        if not row or row["status"] != "active":
            raise WardenAPIError(
                "expired_session", "Connect session is expired or already used"
            )
        return {
            "allowed_providers": payload["providers"],
            "expires_at": datetime.fromtimestamp(
                cast(int, payload["exp"]), timezone.utc
            ).isoformat(),
        }

    def consume(self, token: str, provider_id: str) -> dict[str, Any]:
        payload = self._verify(token)
        if provider_id not in payload["providers"]:
            raise WardenAPIError(
                "invalid_scope", "Provider is not allowed by this Connect session"
            )
        with self.database.connect() as connection:
            updated = connection.execute(
                """UPDATE connect_sessions SET status='consumed',consumed_at=?
                WHERE session_id=? AND token_hash=? AND status='active' AND expires_at>?""",
                (
                    _now().isoformat(),
                    payload["sid"],
                    hashlib.sha256(token.encode()).hexdigest(),
                    _now().isoformat(),
                ),
            )
            if updated.rowcount != 1:
                raise WardenAPIError(
                    "expired_session", "Connect session is expired or already used"
                )
        self.audit.append(
            "connect_session.consumed",
            payload["sub"],
            principal_id=payload["sub"],
            agent_id=payload.get("agent_id"),
            payload={"session_id": payload["sid"], "provider_id": provider_id},
        )
        return payload

    def revoke_for_principal(self, principal_id: str) -> int:
        with self.database.connect() as connection:
            result = connection.execute(
                "UPDATE connect_sessions SET status='revoked' WHERE principal_id=? AND status='active'",
                (principal_id,),
            )
            return result.rowcount

    def _verify(self, token: str) -> dict[str, Any]:
        try:
            encoded, supplied = token.removeprefix("wcs_").split(".", 1)
            expected = _b64(
                hmac.new(self._signing_key, encoded.encode(), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(supplied, expected):
                raise ValueError
            payload = json.loads(_unb64(encoded))
        except Exception as exc:
            raise WardenAPIError(
                "invalid_request", "Connect session token is invalid"
            ) from exc
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= int(
            _now().timestamp()
        ):
            raise WardenAPIError("expired_session", "Connect session has expired")
        return payload
