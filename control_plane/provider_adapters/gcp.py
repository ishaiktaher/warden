"""Google Cloud KMS, Secret Manager, and immutable Storage adapters."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

from ..config import Settings
from ..providers import ProviderError, SigningKey


def _secret_id(name: str) -> str:
    return "warden-" + hashlib.sha256(name.encode()).hexdigest()


def _crc_value(value: Any) -> int:
    return int(getattr(value, "value", value))


class GcpKmsSigningProvider:
    name = "gcp_kms"

    def __init__(self, settings: Settings):
        if not settings.signing_key_id:
            raise ProviderError("gcp_kms requires WARDEN_SIGNING_KEY_ID")
        try:
            from google.cloud import kms
        except ImportError as exc:
            raise ProviderError("Install requirements-gcp.txt for gcp_kms") from exc
        self.kms = kms
        self.client = kms.KeyManagementServiceClient()
        self.key_id = settings.signing_key_id

    def active_key(self) -> SigningKey:
        try:
            key = self.client.get_public_key(request={"name": self.key_id})
            algorithm = self.kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm(
                key.algorithm
            ).name
            if "RSA_SIGN_PKCS1" not in algorithm or "SHA256" not in algorithm:
                raise ProviderError("Google Cloud KMS key does not support RS256")
            parsed = serialization.load_pem_public_key(key.pem.encode())
            public_pem = parsed.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Google Cloud KMS public key is unavailable") from exc
        return SigningKey(self.key_id, "RS256", public_pem)

    def sign(self, key_id: str, message: bytes) -> bytes:
        try:
            import google_crc32c

            digest = hashlib.sha256(message).digest()
            checksum = google_crc32c.value(digest)
            response = self.client.asymmetric_sign(request={
                "name": key_id,
                "digest": {"sha256": digest},
                "digest_crc32c": checksum,
            })
            if not response.verified_digest_crc32c:
                raise ProviderError("Google Cloud KMS rejected the digest checksum")
            if response.name != key_id:
                raise ProviderError("Google Cloud KMS signed with an unexpected key")
            if _crc_value(response.signature_crc32c) != google_crc32c.value(response.signature):
                raise ProviderError("Google Cloud KMS signature checksum is invalid")
            return bytes(response.signature)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Google Cloud KMS signing failed") from exc


class GcpSecretsProvider:
    name = "gcp_secret_manager"

    def __init__(self, settings: Settings):
        if not settings.secrets_prefix:
            raise ProviderError(
                "gcp_secret_manager requires WARDEN_SECRETS_PREFIX=projects/PROJECT_ID"
            )
        try:
            from google.cloud import secretmanager
        except ImportError as exc:
            raise ProviderError("Install requirements-gcp.txt for gcp_secret_manager") from exc
        self.client = secretmanager.SecretManagerServiceClient()
        self.parent = settings.secrets_prefix.rstrip("/")
        if not self.parent.startswith("projects/"):
            raise ProviderError("Google Secret Manager prefix must be projects/PROJECT_ID")

    def put(self, name: str, value: str) -> str:
        secret_id = _secret_id(name)
        secret_name = f"{self.parent}/secrets/{secret_id}"
        try:
            from google.api_core.exceptions import NotFound

            try:
                self.client.get_secret(request={"name": secret_name})
            except NotFound:
                self.client.create_secret(request={
                    "parent": self.parent, "secret_id": secret_id,
                    "secret": {"replication": {"automatic": {}}},
                })
            version = self.client.add_secret_version(request={
                "parent": secret_name, "payload": {"data": value.encode()}
            })
            return str(version.name)
        except Exception as exc:
            raise ProviderError("Google Secret Manager secret could not be stored") from exc

    def get(self, reference: str) -> str:
        if not reference.startswith(self.parent + "/secrets/"):
            raise ProviderError("Google secret reference belongs to a different project")
        try:
            response = self.client.access_secret_version(request={"name": reference})
            return bytes(response.payload.data).decode()
        except Exception as exc:
            raise ProviderError("Google secret could not be resolved") from exc

    def revoke(self, reference: str) -> None:
        if not reference.startswith(self.parent + "/secrets/"):
            raise ProviderError("Google secret reference belongs to a different project")
        try:
            self.client.destroy_secret_version(request={"name": reference})
        except Exception as exc:
            raise ProviderError("Google secret could not be revoked") from exc


class GcpStorageAuditProvider:
    """Requires a bucket with a locked retention policy."""

    name = "gcp_storage"

    def __init__(self, settings: Settings):
        if not settings.audit_target:
            raise ProviderError("gcp_storage requires WARDEN_AUDIT_TARGET")
        try:
            from google.cloud import storage
        except ImportError as exc:
            raise ProviderError("Install requirements-gcp.txt for gcp_storage") from exc
        self.bucket_name = settings.audit_target
        self.bucket = storage.Client().bucket(self.bucket_name)

    def anchor(self, document: bytes, retention_days: int) -> dict[str, Any]:
        timestamp = datetime.now(timezone.utc)
        key = f"audit-anchors/{timestamp:%Y/%m/%d}/{uuid4()}.json"
        try:
            self.bucket.reload()
            required_seconds = retention_days * 86_400
            if not self.bucket.retention_policy_locked:
                raise ProviderError("Google Cloud Storage retention policy is not locked")
            if not self.bucket.retention_period or self.bucket.retention_period < required_seconds:
                raise ProviderError("Google Cloud Storage retention period is too short")
            blob = self.bucket.blob(key)
            blob.upload_from_string(
                document, content_type="application/json", if_generation_match=0
            )
            blob.reload()
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("Google Cloud Storage audit anchor failed") from exc
        return {
            "target": self.bucket_name,
            "key": key,
            "generation": str(blob.generation),
            "retention_expiration_time": (
                blob.retention_expiration_time.isoformat()
                if blob.retention_expiration_time else None
            ),
        }
