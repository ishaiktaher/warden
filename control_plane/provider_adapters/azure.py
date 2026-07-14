"""Azure Key Vault and immutable Blob Storage provider adapters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..config import Settings
from ..providers import ProviderError, SigningKey


def _secret_name(name: str) -> str:
    return "warden-" + hashlib.sha256(name.encode()).hexdigest()


def _key_parts(identifier: str) -> tuple[str, str, str | None]:
    parsed = urlparse(identifier)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme != "https" or len(parts) not in (2, 3) or parts[0] != "keys":
        raise ProviderError("Azure signing key ID must be a Key Vault key URL")
    return f"https://{parsed.netloc}", parts[1], parts[2] if len(parts) == 3 else None


def _secret_parts(identifier: str) -> tuple[str, str, str | None]:
    parsed = urlparse(identifier)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme != "https" or len(parts) not in (2, 3) or parts[0] != "secrets":
        raise ProviderError("Azure secret reference is invalid")
    return f"https://{parsed.netloc}", parts[1], parts[2] if len(parts) == 3 else None


class AzureKeyVaultSigningProvider:
    name = "azure_key_vault"

    def __init__(self, settings: Settings):
        if not settings.signing_key_id:
            raise ProviderError("azure_key_vault signing requires WARDEN_SIGNING_KEY_ID")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient
        except ImportError as exc:
            raise ProviderError("Install requirements-azure.txt for azure_key_vault") from exc
        vault_url, key_name, key_version = _key_parts(settings.signing_key_id)
        credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=vault_url, credential=credential)
        self.crypto_type = CryptographyClient
        self.credential = credential
        self.key_name = key_name
        self.key_version = key_version

    def active_key(self) -> SigningKey:
        try:
            key = self.key_client.get_key(self.key_name, self.key_version)
            if not key.id or not key.key or not key.key.n or not key.key.e:
                raise ProviderError("Azure Key Vault key omitted RSA public key material")
            public = rsa.RSAPublicNumbers(
                int.from_bytes(key.key.e, "big"), int.from_bytes(key.key.n, "big")
            ).public_key()
            public_pem = public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Azure Key Vault public key is unavailable") from exc
        return SigningKey(str(key.id), "RS256", public_pem)

    def sign(self, key_id: str, message: bytes) -> bytes:
        try:
            from azure.keyvault.keys.crypto import SignatureAlgorithm
            from cryptography.hazmat.primitives import hashes

            digest = hashes.Hash(hashes.SHA256())
            digest.update(message)
            client = self.crypto_type(key_id, credential=self.credential)
            return bytes(client.sign(SignatureAlgorithm.rs256, digest.finalize()).signature)
        except Exception as exc:
            raise ProviderError("Azure Key Vault signing failed") from exc


class AzureKeyVaultSecretsProvider:
    name = "azure_key_vault"

    def __init__(self, settings: Settings):
        if not settings.secrets_provider_url:
            raise ProviderError("azure_key_vault secrets requires WARDEN_SECRETS_PROVIDER_URL")
        if settings.production and not settings.secrets_provider_url.startswith("https://"):
            raise ProviderError("Azure Key Vault URL must use HTTPS in production")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise ProviderError("Install requirements-azure.txt for azure_key_vault") from exc
        self.vault_url = settings.secrets_provider_url.rstrip("/")
        self.client = SecretClient(
            vault_url=self.vault_url, credential=DefaultAzureCredential()
        )

    def put(self, name: str, value: str) -> str:
        try:
            secret = self.client.set_secret(_secret_name(name), value)
            if not secret.id:
                raise ProviderError("Azure Key Vault omitted the secret reference")
            return str(secret.id)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Azure secret could not be stored") from exc

    def get(self, reference: str) -> str:
        vault_url, name, version = _secret_parts(reference)
        if vault_url != self.vault_url:
            raise ProviderError("Azure secret reference belongs to a different vault")
        try:
            value = self.client.get_secret(name, version).value
            if not isinstance(value, str):
                raise ProviderError("Azure Key Vault omitted the secret value")
            return value
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Azure secret could not be resolved") from exc

    def revoke(self, reference: str) -> None:
        vault_url, name, _ = _secret_parts(reference)
        if vault_url != self.vault_url:
            raise ProviderError("Azure secret reference belongs to a different vault")
        try:
            self.client.begin_delete_secret(name).result()
        except Exception as exc:
            raise ProviderError("Azure secret could not be revoked") from exc


class AzureBlobAuditProvider:
    """Anchors audit heads with a locked, per-blob immutability policy."""

    name = "azure_blob"

    def __init__(self, settings: Settings):
        if not settings.audit_provider_url or not settings.audit_target:
            raise ProviderError(
                "azure_blob requires WARDEN_AUDIT_PROVIDER_URL and WARDEN_AUDIT_TARGET"
            )
        if settings.production and not settings.audit_provider_url.startswith("https://"):
            raise ProviderError("Azure Blob account URL must use HTTPS in production")
        try:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise ProviderError("Install requirements-azure.txt for azure_blob") from exc
        service = BlobServiceClient(
            account_url=settings.audit_provider_url,
            credential=DefaultAzureCredential(),
        )
        self.container = settings.audit_target
        self.container_client = service.get_container_client(self.container)

    def anchor(self, document: bytes, retention_days: int) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc)
        key = f"audit-anchors/{timestamp:%Y/%m/%d}/{uuid4()}.json"
        try:
            from azure.storage.blob import ContentSettings, ImmutabilityPolicy

            blob = self.container_client.get_blob_client(key)
            response = blob.upload_blob(
                document, blob_type="BlockBlob", overwrite=False,
                content_settings=ContentSettings(content_type="application/json"),
            )
            retain_until = timestamp + timedelta(days=retention_days)
            policy = blob.set_immutability_policy(ImmutabilityPolicy(
                expiry_time=retain_until, policy_mode="Locked"
            ))
        except Exception as exc:
            raise ProviderError("Azure Blob immutable audit anchor failed") from exc
        return {
            "target": self.container,
            "key": key,
            "etag": response.get("etag") if isinstance(response, dict) else None,
            "retained_until": getattr(policy, "expiry_time", retain_until).isoformat(),
        }
