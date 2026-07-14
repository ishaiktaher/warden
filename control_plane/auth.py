"""OIDC authentication and workload-principal binding.

The development header mode is deliberately unavailable when
``CONTROL_PLANE_ENV=prod``. Production callers must present an OIDC access
token issued for Warden's configured audience.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import threading
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import requests

from .config import Settings


class AuthenticationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[str]
    token_id: str | None = None
    on_behalf_of: str | None = None

    def require_any_role(self, *roles: str) -> None:
        if not self.roles.intersection(roles):
            raise AuthenticationError("Principal lacks the required role")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _integer(value: str) -> int:
    return int.from_bytes(_decode(value), "big")


class OIDCAuthenticator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._keys: dict[str, dict[str, Any]] = {}
        self._keys_expire_at = 0.0
        self._lock = threading.Lock()

    def authenticate(self, authorization: str | None) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthenticationError("A bearer access token is required")
        if not self.settings.oidc_issuer or not self.settings.oidc_audience:
            raise AuthenticationError("OIDC authentication is not configured")
        token = authorization[7:].strip()
        try:
            header_part, payload_part, signature_part = token.split(".")
            header = json.loads(_decode(header_part))
            claims = json.loads(_decode(payload_part))
        except Exception as exc:
            raise AuthenticationError("Malformed access token") from exc
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise AuthenticationError("Unsupported access-token algorithm")
        jwk = self._key(header["kid"])
        try:
            public_key = rsa.RSAPublicNumbers(
                _integer(jwk["e"]), _integer(jwk["n"])
            ).public_key()
            public_key.verify(
                _decode(signature_part), f"{header_part}.{payload_part}".encode(),
                padding.PKCS1v15(), hashes.SHA256(),
            )
        except Exception as exc:
            raise AuthenticationError("Invalid access-token signature") from exc
        now = int(time.time())
        issuer = str(claims.get("iss", "")).rstrip("/")
        audiences = claims.get("aud", [])
        audiences = [audiences] if isinstance(audiences, str) else audiences
        if issuer != self.settings.oidc_issuer:
            raise AuthenticationError("Access-token issuer mismatch")
        if self.settings.oidc_audience not in audiences:
            raise AuthenticationError("Access-token audience mismatch")
        if not isinstance(claims.get("exp"), int) or claims["exp"] <= now:
            raise AuthenticationError("Access token is expired")
        if isinstance(claims.get("nbf"), int) and claims["nbf"] > now + 30:
            raise AuthenticationError("Access token is not active")
        subject = claims.get("sub")
        tenant = claims.get(self.settings.oidc_tenant_claim)
        if not isinstance(subject, str) or not isinstance(tenant, str):
            raise AuthenticationError("Access token lacks subject or tenant identity")
        roles = claims.get(self.settings.oidc_roles_claim, [])
        if isinstance(roles, str):
            roles = roles.split()
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise AuthenticationError("Access-token roles claim is invalid")
        on_behalf_of = claims.get(self.settings.oidc_on_behalf_of_claim)
        if on_behalf_of is not None and not isinstance(on_behalf_of, str):
            raise AuthenticationError("Access-token on-behalf-of claim is invalid")
        return Principal(
            subject, tenant, frozenset(roles), claims.get("jti"), on_behalf_of
        )

    def _key(self, kid: str) -> dict[str, Any]:
        now = time.monotonic()
        if now >= self._keys_expire_at or kid not in self._keys:
            with self._lock:
                if now >= self._keys_expire_at or kid not in self._keys:
                    self._refresh()
        key = self._keys.get(kid)
        if not key:
            raise AuthenticationError("Access-token signing key is unknown")
        return key

    def _refresh(self) -> None:
        issuer = self.settings.oidc_issuer
        if not issuer:
            raise AuthenticationError("OIDC issuer is not configured")
        try:
            discovery = requests.get(
                f"{issuer}/.well-known/openid-configuration", timeout=5
            )
            discovery.raise_for_status()
            jwks_uri = discovery.json()["jwks_uri"]
            if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
                raise AuthenticationError("OIDC discovery returned an unsafe JWKS URI")
            jwks = requests.get(jwks_uri, timeout=5)
            jwks.raise_for_status()
            keys = jwks.json()["keys"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise AuthenticationError("OIDC signing keys are unavailable") from exc
        self._keys = {
            key["kid"]: key for key in keys
            if key.get("kty") == "RSA" and key.get("use", "sig") == "sig"
        }
        self._keys_expire_at = time.monotonic() + self.settings.oidc_jwks_cache_seconds
