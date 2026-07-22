"""Scoped API key issuance and authentication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import secrets
from typing import Any
from uuid import uuid4

from .audit import AuditLedger
from .database import Database
from .errors import WardenAPIError


def _now() -> datetime:
    return datetime.now(timezone.utc)


class APIKeyService:
    PREFIXES = {"runtime": "warden_rk_", "agent": "warden_ak_", "derived": "warden_dk_"}

    def __init__(self, database: Database, audit: AuditLedger):
        self.database = database
        self.audit = audit

    def mint(
        self,
        *,
        key_type: str,
        name: str,
        scopes: list[str],
        agent_id: str | None,
        expires_in: int | None,
        cidr_allowlist: list[str],
        parent_key_id: str | None,
        actor: str,
    ) -> dict[str, Any]:
        if key_type not in self.PREFIXES or not scopes:
            raise WardenAPIError(
                "invalid_scope", "A valid key type and at least one scope are required"
            )
        if key_type == "agent" and not agent_id:
            raise WardenAPIError("invalid_request", "Agent keys require agent_id")
        parent = None
        if key_type == "derived":
            parent = self.database.one(
                "SELECT * FROM api_keys WHERE key_id=?", (parent_key_id,)
            )
            if not parent or parent["status"] != "active":
                raise WardenAPIError(
                    "invalid_key", "Derived keys require an active parent key"
                )
            if not set(scopes).issubset(set(json.loads(parent["scopes"]))):
                raise WardenAPIError(
                    "invalid_scope", "Derived-key scopes must narrow the parent"
                )
        networks = []
        try:
            networks = [
                str(ipaddress.ip_network(item, strict=False)) for item in cidr_allowlist
            ]
        except ValueError as exc:
            raise WardenAPIError(
                "invalid_request", "CIDR allowlist contains an invalid network"
            ) from exc
        key_id = str(uuid4())
        plaintext = self.PREFIXES[key_type] + secrets.token_urlsafe(32)
        created = _now()
        expires_at = created + timedelta(seconds=expires_in) if expires_in else None
        self.database.execute(
            """INSERT INTO api_keys(key_id,key_type,name,key_prefix,key_hash,scopes,agent_id,
            parent_key_id,cidr_allowlist,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                key_id,
                key_type,
                name,
                plaintext[:16],
                hashlib.sha256(plaintext.encode()).hexdigest(),
                json.dumps(sorted(set(scopes))),
                agent_id,
                parent_key_id,
                json.dumps(networks),
                "active",
                created.isoformat(),
                expires_at.isoformat() if expires_at else None,
            ),
        )
        self.audit.append(
            "api_key.minted",
            actor,
            agent_id=agent_id,
            payload={
                "key_id": key_id,
                "key_type": key_type,
                "key_prefix": plaintext[:16],
                "scopes": scopes,
            },
        )
        return {**self.get(key_id), "api_key": plaintext}

    def authenticate(
        self, plaintext: str, required_scope: str, client_ip: str | None
    ) -> dict[str, Any]:
        digest = hashlib.sha256(plaintext.encode()).hexdigest()
        row = self.database.one("SELECT * FROM api_keys WHERE key_hash=?", (digest,))
        if not row:
            raise WardenAPIError("invalid_key", "API key is invalid")
        if row["status"] == "revoked":
            raise WardenAPIError("revoked", "API key has been revoked")
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= _now():
            raise WardenAPIError("revoked", "API key has expired")
        if required_scope not in json.loads(row["scopes"]):
            raise WardenAPIError("invalid_scope", f"API key lacks {required_scope}")
        networks = [
            ipaddress.ip_network(item) for item in json.loads(row["cidr_allowlist"])
        ]
        if networks:
            try:
                address = ipaddress.ip_address(client_ip or "")
            except ValueError as exc:
                raise WardenAPIError(
                    "forbidden", "API key requires an allowed client IP"
                ) from exc
            if not any(address in network for network in networks):
                raise WardenAPIError(
                    "forbidden", "Client IP is outside the API key allowlist"
                )
        self.database.execute(
            "UPDATE api_keys SET last_used_at=? WHERE key_id=?",
            (_now().isoformat(), row["key_id"]),
        )
        return self._public(row)

    def get(self, key_id: str) -> dict[str, Any]:
        row = self.database.one("SELECT * FROM api_keys WHERE key_id=?", (key_id,))
        if not row:
            raise WardenAPIError("not_found", "API key was not found")
        return self._public(row)

    def list(self, *, agent_id: str | None = None) -> list[dict[str, Any]]:
        rows = self.database.all(
            "SELECT * FROM api_keys"
            + (" WHERE agent_id=?" if agent_id else "")
            + " ORDER BY created_at",
            (agent_id,) if agent_id else (),
        )
        return [self._public(row) for row in rows]

    def deprecate(self, key_id: str, actor: str) -> dict[str, Any]:
        self._transition(key_id, "deprecated", actor)
        return self.get(key_id)

    def revoke(self, key_id: str, actor: str) -> dict[str, Any]:
        if not self.database.one(
            "SELECT key_id FROM api_keys WHERE key_id=?", (key_id,)
        ):
            raise WardenAPIError("not_found", "API key was not found")
        now = _now().isoformat()
        with self.database.connect() as connection:
            connection.execute(
                """WITH RECURSIVE descendants(key_id) AS (
                SELECT key_id FROM api_keys WHERE key_id=? UNION ALL
                SELECT child.key_id FROM api_keys child JOIN descendants d ON child.parent_key_id=d.key_id
            ) UPDATE api_keys SET status='revoked',revoked_at=? WHERE key_id IN (SELECT key_id FROM descendants)""",
                (key_id, now),
            )
        self.audit.append(
            "api_key.revoked", actor, payload={"key_id": key_id, "cascade": True}
        )
        return self.get(key_id)

    def revoke_for_agent(self, agent_id: str, actor: str) -> int:
        rows = self.database.all(
            "SELECT key_id FROM api_keys WHERE agent_id=? AND status!='revoked'",
            (agent_id,),
        )
        for row in rows:
            self.revoke(row["key_id"], actor)
        return len(rows)

    def _transition(self, key_id: str, status: str, actor: str) -> None:
        with self.database.connect() as connection:
            result = connection.execute(
                "UPDATE api_keys SET status=?,deprecated_at=? WHERE key_id=? AND status='active'",
                (status, _now().isoformat(), key_id),
            )
            if result.rowcount != 1:
                raise WardenAPIError("conflict", "Only an active key can be deprecated")
        self.audit.append(f"api_key.{status}", actor, payload={"key_id": key_id})

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        return {
            key: (
                json.loads(row[key])
                if key in {"scopes", "cidr_allowlist"}
                else row[key]
            )
            for key in (
                "key_id",
                "key_type",
                "name",
                "key_prefix",
                "scopes",
                "agent_id",
                "parent_key_id",
                "cidr_allowlist",
                "status",
                "created_at",
                "expires_at",
                "deprecated_at",
                "revoked_at",
                "last_used_at",
            )
        }
