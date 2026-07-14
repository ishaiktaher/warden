"""Vendor-neutral ports and optional infrastructure adapters.

Warden core knows only these protocols. A provider may be selected by a built-in
name or by ``package.module:factory``. A custom factory receives ``Settings`` and
returns an object implementing the selected protocol.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from typing import Any, Protocol, cast
from urllib.parse import quote
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
import requests

from .config import Settings


class ProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class SigningKey:
    key_id: str
    algorithm: str
    public_pem: str


class SigningProvider(Protocol):
    name: str
    def active_key(self) -> SigningKey: ...
    def sign(self, key_id: str, message: bytes) -> bytes: ...


class SecretsProvider(Protocol):
    name: str
    def put(self, name: str, value: str) -> str: ...
    def get(self, reference: str) -> str: ...
    def revoke(self, reference: str) -> None: ...


class AuditAnchorProvider(Protocol):
    name: str
    def anchor(self, document: bytes, retention_days: int) -> dict[str, Any]: ...


def _load_custom(spec: str, settings: Settings) -> Any:
    if ":" not in spec:
        raise ProviderError(f"Unknown provider: {spec}")
    module_name, factory_name = spec.rsplit(":", 1)
    try:
        factory = getattr(importlib.import_module(module_name), factory_name)
        return factory(settings)
    except Exception as exc:
        raise ProviderError(f"Custom provider could not be loaded: {spec}") from exc


def signing_provider(settings: Settings) -> SigningProvider | None:
    spec = settings.signing_provider
    if spec == "local":
        if settings.production:
            raise ProviderError("Local signing is forbidden in production")
        return None
    if spec == "http":
        return HttpSigningProvider(settings)
    if spec == "aws_kms":
        return AwsKmsSigningProvider(settings)
    if spec == "azure_key_vault":
        from .provider_adapters.azure import AzureKeyVaultSigningProvider
        return AzureKeyVaultSigningProvider(settings)
    if spec == "gcp_kms":
        from .provider_adapters.gcp import GcpKmsSigningProvider
        return GcpKmsSigningProvider(settings)
    if spec == "vault_transit":
        from .provider_adapters.vault import VaultTransitSigningProvider
        return VaultTransitSigningProvider(settings)
    if spec == "pkcs11":
        from .provider_adapters.pkcs11 import Pkcs11SigningProvider
        return Pkcs11SigningProvider(settings)
    return cast(SigningProvider, _load_custom(spec, settings))


def secrets_provider(settings: Settings) -> SecretsProvider | None:
    spec = settings.secrets_provider
    if spec == "local":
        if settings.production:
            raise ProviderError("Local secret storage is forbidden in production")
        return None
    if spec == "http":
        return HttpSecretsProvider(settings)
    if spec == "aws_secrets_manager":
        return AwsSecretsProvider(settings)
    if spec == "azure_key_vault":
        from .provider_adapters.azure import AzureKeyVaultSecretsProvider
        return AzureKeyVaultSecretsProvider(settings)
    if spec == "gcp_secret_manager":
        from .provider_adapters.gcp import GcpSecretsProvider
        return GcpSecretsProvider(settings)
    if spec == "vault_kv2":
        from .provider_adapters.vault import VaultKv2SecretsProvider
        return VaultKv2SecretsProvider(settings)
    return cast(SecretsProvider, _load_custom(spec, settings))


def audit_provider(settings: Settings) -> AuditAnchorProvider | None:
    spec = settings.audit_provider
    if spec == "local":
        if settings.production:
            raise ProviderError("Local audit anchoring is forbidden in production")
        return None
    if spec == "http":
        return HttpAuditProvider(settings)
    if spec == "aws_s3":
        return AwsS3AuditProvider(settings)
    if spec == "azure_blob":
        from .provider_adapters.azure import AzureBlobAuditProvider
        return AzureBlobAuditProvider(settings)
    if spec == "gcp_storage":
        from .provider_adapters.gcp import GcpStorageAuditProvider
        return GcpStorageAuditProvider(settings)
    return cast(AuditAnchorProvider, _load_custom(spec, settings))


class _HttpBase:
    def __init__(self, endpoint: str | None, token: str | None):
        if not endpoint or not endpoint.startswith("https://"):
            raise ProviderError("HTTP provider endpoint must use HTTPS")
        self.endpoint = endpoint.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = requests.request(
                method, self.endpoint + path, headers=self.headers,
                timeout=10, allow_redirects=False, **kwargs,
            )
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise ProviderError("Infrastructure provider request failed") from exc
        if not isinstance(result, dict):
            raise ProviderError("Infrastructure provider returned an invalid response")
        return result


class HttpSigningProvider(_HttpBase):
    name = "http"
    def __init__(self, settings: Settings):
        super().__init__(settings.signing_provider_url, settings.provider_auth_token)

    def active_key(self) -> SigningKey:
        value = self.request("GET", "/v1/signing-key")
        try:
            return SigningKey(value["key_id"], value.get("algorithm", "RS256"), value["public_key_pem"])
        except KeyError as exc:
            raise ProviderError("Signing provider omitted key metadata") from exc

    def sign(self, key_id: str, message: bytes) -> bytes:
        value = self.request("POST", "/v1/sign", json={
            "key_id": key_id, "algorithm": "RS256",
            "message_base64": base64.b64encode(message).decode(),
        })
        try:
            return base64.b64decode(value["signature_base64"], validate=True)
        except Exception as exc:
            raise ProviderError("Signing provider returned an invalid signature") from exc


class HttpSecretsProvider(_HttpBase):
    name = "http"
    def __init__(self, settings: Settings):
        super().__init__(settings.secrets_provider_url, settings.provider_auth_token)

    def put(self, name: str, value: str) -> str:
        result = self.request("PUT", f"/v1/secrets/{quote(name, safe='')}", json={"value": value})
        return str(result.get("reference") or name)

    def get(self, reference: str) -> str:
        result = self.request("GET", f"/v1/secrets/{quote(reference, safe='')}")
        if not isinstance(result.get("value"), str):
            raise ProviderError("Secrets provider omitted the secret value")
        return result["value"]

    def revoke(self, reference: str) -> None:
        self.request("DELETE", f"/v1/secrets/{quote(reference, safe='')}")


class HttpAuditProvider(_HttpBase):
    name = "http"
    def __init__(self, settings: Settings):
        super().__init__(settings.audit_provider_url, settings.provider_auth_token)

    def anchor(self, document: bytes, retention_days: int) -> dict[str, Any]:
        return self.request("POST", "/v1/audit-anchors", json={
            "document_base64": base64.b64encode(document).decode(),
            "sha256": hashlib.sha256(document).hexdigest(),
            "retention_days": retention_days,
        })


class AwsKmsSigningProvider:
    name = "aws_kms"
    def __init__(self, settings: Settings):
        if not settings.provider_region or not settings.signing_key_id:
            raise ProviderError("aws_kms requires WARDEN_PROVIDER_REGION and WARDEN_SIGNING_KEY_ID")
        import boto3
        self.client = boto3.client("kms", region_name=settings.provider_region)
        self.key_id = settings.signing_key_id

    def active_key(self) -> SigningKey:
        try:
            response = self.client.get_public_key(KeyId=self.key_id)
            if "RSASSA_PKCS1_V1_5_SHA_256" not in response.get("SigningAlgorithms", []):
                raise ProviderError("AWS KMS key does not support RS256")
            key = serialization.load_der_public_key(response["PublicKey"])
            public_pem = key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("AWS KMS public key is unavailable") from exc
        kid = "aws-kms-" + hashlib.sha256(self.key_id.encode()).hexdigest()[:20]
        return SigningKey(kid, "RS256", public_pem)

    def sign(self, key_id: str, message: bytes) -> bytes:
        del key_id
        try:
            return self.client.sign(
                KeyId=self.key_id, Message=message, MessageType="RAW",
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
            )["Signature"]
        except Exception as exc:
            raise ProviderError("AWS KMS signing failed") from exc


class AwsSecretsProvider:
    name = "aws_secrets_manager"
    def __init__(self, settings: Settings):
        if not settings.provider_region or not settings.secrets_prefix:
            raise ProviderError("aws_secrets_manager requires WARDEN_PROVIDER_REGION and WARDEN_SECRETS_PREFIX")
        import boto3
        self.client = boto3.client("secretsmanager", region_name=settings.provider_region)
        self.prefix = settings.secrets_prefix.rstrip("/")

    def put(self, name: str, value: str) -> str:
        reference = f"{self.prefix}/{name}"
        try:
            self.client.put_secret_value(SecretId=reference, SecretString=value)
        except self.client.exceptions.ResourceNotFoundException:
            self.client.create_secret(Name=reference, SecretString=value)
        return reference

    def get(self, reference: str) -> str:
        try:
            return self.client.get_secret_value(SecretId=reference)["SecretString"]
        except Exception as exc:
            raise ProviderError("AWS secret could not be resolved") from exc

    def revoke(self, reference: str) -> None:
        self.client.delete_secret(SecretId=reference, RecoveryWindowInDays=30)


class AwsS3AuditProvider:
    name = "aws_s3"
    def __init__(self, settings: Settings):
        if not settings.provider_region or not settings.audit_target:
            raise ProviderError("aws_s3 requires WARDEN_PROVIDER_REGION and WARDEN_AUDIT_TARGET")
        import boto3
        self.client = boto3.client("s3", region_name=settings.provider_region)
        self.bucket = settings.audit_target

    def anchor(self, document: bytes, retention_days: int) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc)
        key = f"audit-anchors/{timestamp:%Y/%m/%d}/{uuid4()}.json"
        try:
            response = self.client.put_object(
                Bucket=self.bucket, Key=key, Body=document,
                ContentType="application/json", ServerSideEncryption="aws:kms",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=timestamp + timedelta(days=retention_days),
            )
        except Exception as exc:
            raise ProviderError("AWS S3 audit anchor failed") from exc
        return {"target": self.bucket, "key": key, "version_id": response.get("VersionId")}
