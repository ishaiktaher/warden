"""HashiCorp Vault Transit and KV v2 adapters using Vault's HTTP API."""

from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import quote

import requests

from ..config import Settings
from ..providers import ProviderError, SigningKey


class _VaultClient:
    def __init__(self, settings: Settings, endpoint: str | None):
        if not endpoint:
            raise ProviderError("Vault provider URL is required")
        if settings.production and not endpoint.startswith("https://"):
            raise ProviderError("Vault provider URL must use HTTPS in production")
        if not endpoint.startswith(("https://", "http://")):
            raise ProviderError("Vault provider URL is invalid")
        if not settings.provider_auth_token:
            raise ProviderError("Vault requires WARDEN_PROVIDER_AUTH_TOKEN")
        self.endpoint = endpoint.rstrip("/")
        self.headers = {"X-Vault-Token": settings.provider_auth_token}
        if settings.provider_namespace:
            self.headers["X-Vault-Namespace"] = settings.provider_namespace

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = requests.request(
                method, self.endpoint + "/v1/" + path.lstrip("/"),
                headers=self.headers, timeout=10, allow_redirects=False, **kwargs,
            )
            response.raise_for_status()
            if response.status_code == 204 or not response.content:
                return {}
            body = response.json()
            if not isinstance(body, dict):
                raise ProviderError("Vault returned an invalid response")
            return body
        except ProviderError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise ProviderError("Vault request failed") from exc


class VaultTransitSigningProvider:
    name = "vault_transit"

    def __init__(self, settings: Settings):
        if not settings.signing_key_id:
            raise ProviderError("vault_transit requires WARDEN_SIGNING_KEY_ID")
        self.client = _VaultClient(settings, settings.signing_provider_url)
        self.key_name = settings.signing_key_id
        self.mount = (settings.provider_mount or "transit").strip("/")

    def active_key(self) -> SigningKey:
        body = self.client.request(
            "GET", f"{quote(self.mount, safe='/')}/keys/{quote(self.key_name, safe='')}"
        )
        try:
            data = body["data"]
            if data["type"] not in ("rsa-2048", "rsa-3072", "rsa-4096"):
                raise ProviderError("Vault Transit key must be RSA")
            version = int(data["latest_version"])
            public_pem = data["keys"][str(version)]["public_key"]
        except ProviderError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError("Vault Transit omitted key metadata") from exc
        key_id = f"vault-transit:{self.mount}:{self.key_name}:{version}"
        return SigningKey(key_id, "RS256", public_pem)

    def sign(self, key_id: str, message: bytes) -> bytes:
        prefix = f"vault-transit:{self.mount}:{self.key_name}:"
        if not key_id.startswith(prefix):
            raise ProviderError("Vault Transit key ID does not match configured key")
        version = key_id.removeprefix(prefix)
        body = self.client.request(
            "POST",
            f"{quote(self.mount, safe='/')}/sign/{quote(self.key_name, safe='')}/{quote(version, safe='')}",
            json={
                "input": base64.b64encode(message).decode(),
                "hash_algorithm": "sha2-256",
                "signature_algorithm": "pkcs1v15",
            },
        )
        try:
            encoded = body["data"]["signature"].rsplit(":", 1)[1]
            return base64.b64decode(encoded, validate=True)
        except (KeyError, IndexError, ValueError) as exc:
            raise ProviderError("Vault Transit returned an invalid signature") from exc


class VaultKv2SecretsProvider:
    name = "vault_kv2"

    def __init__(self, settings: Settings):
        if not settings.secrets_prefix:
            raise ProviderError("vault_kv2 requires WARDEN_SECRETS_PREFIX=mount/path")
        self.client = _VaultClient(settings, settings.secrets_provider_url)
        parts = settings.secrets_prefix.strip("/").split("/", 1)
        self.mount = parts[0]
        self.base_path = parts[1].rstrip("/") if len(parts) == 2 else "warden"

    def _path(self, name: str) -> str:
        identifier = hashlib.sha256(name.encode()).hexdigest()
        return f"{self.base_path}/{identifier}"

    def put(self, name: str, value: str) -> str:
        path = self._path(name)
        self.client.request(
            "POST", f"{quote(self.mount, safe='')}/data/{quote(path, safe='/')}",
            json={"data": {"value": value}},
        )
        return f"vault-kv2:{self.mount}:{path}"

    def _reference(self, reference: str) -> tuple[str, str]:
        try:
            scheme, mount, path = reference.split(":", 2)
        except ValueError as exc:
            raise ProviderError("Vault KV v2 reference is invalid") from exc
        if scheme != "vault-kv2" or mount != self.mount or not path.startswith(self.base_path + "/"):
            raise ProviderError("Vault KV v2 reference is outside the configured prefix")
        return mount, path

    def get(self, reference: str) -> str:
        mount, path = self._reference(reference)
        body = self.client.request(
            "GET", f"{quote(mount, safe='')}/data/{quote(path, safe='/')}"
        )
        try:
            value = body["data"]["data"]["value"]
            if not isinstance(value, str):
                raise TypeError
            return value
        except (KeyError, TypeError) as exc:
            raise ProviderError("Vault KV v2 omitted the secret value") from exc

    def revoke(self, reference: str) -> None:
        mount, path = self._reference(reference)
        self.client.request(
            "DELETE", f"{quote(mount, safe='')}/metadata/{quote(path, safe='/')}"
        )
