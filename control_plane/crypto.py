"""RS256 capability tokens, key rotation, verification and delegation controls."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import time
from typing import Any, cast
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .audit import AuditLedger
from .config import Settings
from .database import Database
from .resources import ResourceError, resource_matches
from .providers import signing_provider


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapabilityError(RuntimeError):
    pass


class CapabilityService:
    def __init__(self, database: Database, audit: AuditLedger, settings: Settings):
        self.database = database
        self.audit = audit
        self.settings = settings
        self.signer = signing_provider(settings)
        if self.signer:
            self._register_external_key("system-bootstrap")
        elif not self.database.one("SELECT kid FROM signing_keys WHERE status='active'"):
            self.rotate_key("system-bootstrap")

    def rotate_key(self, actor: str) -> str:
        if self.signer:
            return self._register_external_key(actor)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        kid = f"key-{uuid4()}"
        now = _now_iso()
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE signing_keys SET status='retired', retired_at=? WHERE status='active'",
                (now,),
            )
            connection.execute(
                "INSERT INTO signing_keys VALUES(?,?,?,?,?,?,NULL)",
                (kid, "RS256", public_pem, private_pem, "active", now),
            )
        self.audit.append("key.rotated", actor, payload={"kid": kid, "algorithm": "RS256"})
        return kid

    def public_keys(self) -> list[dict[str, str]]:
        return [
            {"kid": row["kid"], "algorithm": row["algorithm"], "public_pem": row["public_pem"], "status": row["status"]}
            for row in self.database.all("SELECT kid,algorithm,public_pem,status FROM signing_keys")
        ]

    def issue(
        self,
        *,
        agent_id: str,
        run_id: str,
        principal_id: str,
        scopes: list[str],
        resources: list[str],
        ttl_seconds: int,
        delegation_depth: int = 0,
        parent_jti: str | None = None,
        actor: str = "token-service",
    ) -> tuple[str, dict[str, Any]]:
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise CapabilityError("Token TTL must be between 1 and 3600 seconds")
        key = self.database.one("SELECT * FROM signing_keys WHERE status='active'")
        if not key:
            raise CapabilityError("No active signing key")
        now = int(time.time())
        claims = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "sub": agent_id,
            "agent_id": agent_id,
            "run_id": run_id,
            "principal_id": principal_id,
            "scopes": sorted(set(scopes)),
            "resources": sorted(set(resources)),
            "delegation_depth": delegation_depth,
            "parent_jti": parent_jti,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid4()),
        }
        header = {"alg": "RS256", "kid": key["kid"], "typ": "JWT"}
        signing_input = _b64(_json(header)) + "." + _b64(_json(claims))
        if key["algorithm"] == "EXTERNAL_RS256":
            try:
                if not self.signer:
                    raise CapabilityError("External signing provider is unavailable")
                signature = self.signer.sign(key["kid"], signing_input.encode())
            except CapabilityError:
                raise
            except Exception as exc:
                raise CapabilityError("Capability signing provider failed") from exc
        else:
            private_key = cast(rsa.RSAPrivateKey, serialization.load_pem_private_key(
                key["private_pem"].encode(), password=None
            ))
            signature = private_key.sign(
                signing_input.encode(), padding.PKCS1v15(), hashes.SHA256()
            )
        token = signing_input + "." + _b64(signature)
        self.database.execute(
            """INSERT INTO tokens(
            jti,kid,agent_id,run_id,principal_id,scopes,resources,delegation_depth,
            parent_jti,issued_at,expires_at,status,revoked_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)""",
            (
                claims["jti"], key["kid"], agent_id, run_id, principal_id,
                json.dumps(claims["scopes"]), json.dumps(claims["resources"]),
                delegation_depth, parent_jti, now, claims["exp"], "active",
            ),
        )
        self.audit.append(
            "token.issued" if not parent_jti else "token.delegated",
            actor,
            principal_id=principal_id,
            agent_id=agent_id,
            run_id=run_id,
            payload={
                "jti": claims["jti"], "kid": key["kid"], "scopes": claims["scopes"],
                "resources": claims["resources"], "expires_at": claims["exp"],
                "parent_jti": parent_jti, "delegation_depth": delegation_depth,
            },
        )
        return token, claims

    def verify(
        self,
        token: str,
        *,
        expected_action: str | None = None,
        expected_resource: str | None = None,
    ) -> dict[str, Any]:
        try:
            header_part, payload_part, signature_part = token.split(".")
            header = json.loads(_unb64(header_part))
            claims = json.loads(_unb64(payload_part))
        except Exception as exc:
            raise CapabilityError("Malformed capability token") from exc
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise CapabilityError("Unsupported capability algorithm")
        key = self.database.one("SELECT * FROM signing_keys WHERE kid=?", (header["kid"],))
        if not key or key["status"] == "revoked":
            raise CapabilityError("Signing key is unavailable or revoked")
        try:
            public_key = cast(
                rsa.RSAPublicKey,
                serialization.load_pem_public_key(key["public_pem"].encode()),
            )
            public_key.verify(
                _unb64(signature_part),
                f"{header_part}.{payload_part}".encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except Exception as exc:
            raise CapabilityError("Invalid capability signature") from exc
        required = {
            "iss", "aud", "agent_id", "run_id", "principal_id", "scopes",
            "resources", "delegation_depth", "iat", "exp", "jti",
        }
        if not required.issubset(claims):
            raise CapabilityError("Capability is missing required claims")
        if claims["iss"] != self.settings.issuer or claims["aud"] != self.settings.audience:
            raise CapabilityError("Capability issuer or audience mismatch")
        if int(time.time()) >= int(claims["exp"]):
            raise CapabilityError("Capability expired")
        token_row = self.database.one("SELECT status FROM tokens WHERE jti=?", (claims["jti"],))
        if not token_row or token_row["status"] != "active":
            raise CapabilityError("Capability revoked or unknown")
        run = self.database.one("SELECT status,revoked_at FROM runs WHERE run_id=?", (claims["run_id"],))
        if not run or run["status"] != "active" or run["revoked_at"]:
            raise CapabilityError("Runtime session is not active")
        agent = self.database.one("SELECT status,expires_at FROM agents WHERE agent_id=?", (claims["agent_id"],))
        if not agent or agent["status"] != "active":
            raise CapabilityError("Agent is not active")
        if agent["expires_at"] and datetime.fromisoformat(agent["expires_at"]) <= datetime.now(timezone.utc):
            raise CapabilityError("Agent registration expired")
        parent_jti = claims.get("parent_jti")
        visited: set[str] = set()
        while parent_jti:
            if parent_jti in visited:
                raise CapabilityError("Invalid delegation ancestry")
            visited.add(parent_jti)
            parent = self.database.one(
                "SELECT status,parent_jti,expires_at FROM tokens WHERE jti=?", (parent_jti,)
            )
            if not parent or parent["status"] != "active" or int(time.time()) >= int(parent["expires_at"]):
                raise CapabilityError("Parent capability revoked or expired")
            parent_jti = parent["parent_jti"]
        if expected_action and expected_action not in claims["scopes"]:
            raise CapabilityError("Action is outside capability scope")
        if expected_resource:
            try:
                matched = any(
                    resource_matches(expected_resource, pattern)
                    for pattern in claims["resources"]
                )
            except ResourceError as exc:
                raise CapabilityError(str(exc)) from exc
            if not matched:
                raise CapabilityError("Resource is outside capability scope")
        return claims

    def revoke(self, jti: str, actor: str, reason: str) -> None:
        if not self.database.one("SELECT jti FROM tokens WHERE jti=?", (jti,)):
            raise CapabilityError("Unknown token")
        now = _now_iso()
        self.database.execute(
            "UPDATE tokens SET status='revoked',revoked_at=? WHERE jti=?", (now, jti)
        )
        self.audit.append("token.revoked", actor, payload={"jti": jti, "reason": reason})

    def revoke_key(self, kid: str, actor: str, reason: str) -> None:
        row = self.database.one("SELECT status FROM signing_keys WHERE kid=?", (kid,))
        if not row:
            raise CapabilityError("Unknown signing key")
        self.database.execute(
            "UPDATE signing_keys SET status='revoked',retired_at=? WHERE kid=?",
            (_now_iso(), kid),
        )
        self.audit.append("key.revoked", actor, payload={"kid": kid, "reason": reason})

    def _register_external_key(self, actor: str) -> str:
        if not self.signer:
            raise CapabilityError("External signing provider is unavailable")
        try:
            external = self.signer.active_key()
            if external.algorithm != "RS256":
                raise CapabilityError("Signing provider must expose an RS256 key")
            cast(rsa.RSAPublicKey, serialization.load_pem_public_key(external.public_pem.encode()))
        except CapabilityError:
            raise
        except Exception as exc:
            raise CapabilityError("Signing provider key is unavailable") from exc
        current = self.database.one(
            "SELECT kid FROM signing_keys WHERE kid=? AND status='active'",
            (external.key_id,),
        )
        if current:
            self.database.execute(
                "UPDATE signing_keys SET public_pem=? WHERE kid=?",
                (external.public_pem, external.key_id),
            )
            return external.key_id
        now = _now_iso()
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE signing_keys SET status='retired', retired_at=? WHERE status='active'",
                (now,),
            )
            connection.execute(
                """INSERT INTO signing_keys VALUES(?,?,?,?,?,?,NULL)
                ON CONFLICT(kid) DO UPDATE SET public_pem=excluded.public_pem,
                status='active',retired_at=NULL""",
                (external.key_id, "EXTERNAL_RS256", external.public_pem, "", "active", now),
            )
        self.audit.append(
            "key.rotated", actor,
            payload={"kid": external.key_id, "algorithm": "RS256", "custody": self.signer.name},
        )
        return external.key_id
