from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from control_plane.config import Settings
from control_plane.provider_adapters.azure import AzureKeyVaultSigningProvider
from control_plane.provider_adapters.gcp import GcpStorageAuditProvider
from control_plane.provider_adapters.vault import (
    VaultKv2SecretsProvider,
    VaultTransitSigningProvider,
)
from control_plane.providers import (
    ProviderError,
    audit_provider,
    secrets_provider,
    signing_provider,
)


def settings(**changes: object) -> Settings:
    values: dict[str, object] = {
        "database_path": Path("unused"), "data_dir": Path("unused"),
        "issuer": "test", "audience": "test", "admin_key": "test",
        "environment": "test", "allowed_egress_hosts": (),
    }
    values.update(changes)
    return Settings(**values)  # type: ignore[arg-type]


class FakeVaultClient:
    def __init__(self) -> None:
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.calls: list[tuple[str, str, dict]] = []
        self.secret = ""

    def request(self, method: str, path: str, **kwargs: object) -> dict:
        self.calls.append((method, path, kwargs))
        if "/keys/" in path:
            pem = self.private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            return {"data": {
                "type": "rsa-2048", "latest_version": 3,
                "keys": {"3": {"public_key": pem}},
            }}
        if "/sign/" in path:
            payload = kwargs["json"]  # type: ignore[index]
            message = base64.b64decode(payload["input"])  # type: ignore[index]
            signature = self.private.sign(message, padding.PKCS1v15(), hashes.SHA256())
            return {"data": {"signature": "vault:v3:" + base64.b64encode(signature).decode()}}
        if "/data/" in path and method == "POST":
            self.secret = kwargs["json"]["data"]["value"]  # type: ignore[index]
            return {"data": {"version": 1}}
        if "/data/" in path and method == "GET":
            return {"data": {"data": {"value": self.secret}}}
        if "/metadata/" in path and method == "DELETE":
            self.secret = ""
            return {}
        raise AssertionError((method, path))


class NativeProviderTests(unittest.TestCase):
    def test_all_native_provider_names_are_first_class_loader_options(self) -> None:
        cases = [
            ("control_plane.provider_adapters.azure.AzureKeyVaultSigningProvider",
             signing_provider, {"signing_provider": "azure_key_vault"}),
            ("control_plane.provider_adapters.gcp.GcpKmsSigningProvider",
             signing_provider, {"signing_provider": "gcp_kms"}),
            ("control_plane.provider_adapters.vault.VaultTransitSigningProvider",
             signing_provider, {"signing_provider": "vault_transit"}),
            ("control_plane.provider_adapters.pkcs11.Pkcs11SigningProvider",
             signing_provider, {"signing_provider": "pkcs11"}),
            ("control_plane.provider_adapters.azure.AzureKeyVaultSecretsProvider",
             secrets_provider, {"secrets_provider": "azure_key_vault"}),
            ("control_plane.provider_adapters.gcp.GcpSecretsProvider",
             secrets_provider, {"secrets_provider": "gcp_secret_manager"}),
            ("control_plane.provider_adapters.vault.VaultKv2SecretsProvider",
             secrets_provider, {"secrets_provider": "vault_kv2"}),
            ("control_plane.provider_adapters.azure.AzureBlobAuditProvider",
             audit_provider, {"audit_provider": "azure_blob"}),
            ("control_plane.provider_adapters.gcp.GcpStorageAuditProvider",
             audit_provider, {"audit_provider": "gcp_storage"}),
        ]
        sentinel = object()
        for target, loader, configured in cases:
            with self.subTest(target=target), patch(target, return_value=sentinel):
                self.assertIs(sentinel, loader(settings(**configured)))

    def test_vault_transit_produces_verifiable_rs256_signature(self) -> None:
        client = FakeVaultClient()
        provider = VaultTransitSigningProvider.__new__(VaultTransitSigningProvider)
        provider.client = client
        provider.mount = "transit"
        provider.key_name = "warden-signing"
        key = provider.active_key()
        message = b"signed capability"
        signature = provider.sign(key.key_id, message)
        public = serialization.load_pem_public_key(key.public_pem.encode())
        public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
        self.assertEqual("RS256", key.algorithm)
        self.assertIn("transit/sign/warden-signing/3", client.calls[-1][1])

    def test_vault_kv2_round_trip_and_prefix_boundary(self) -> None:
        client = FakeVaultClient()
        provider = VaultKv2SecretsProvider.__new__(VaultKv2SecretsProvider)
        provider.client = client
        provider.mount = "secret"
        provider.base_path = "warden/connectors"
        reference = provider.put("tenant/connector", "sensitive")
        self.assertEqual("sensitive", provider.get(reference))
        provider.revoke(reference)
        self.assertEqual("", client.secret)
        with self.assertRaisesRegex(ProviderError, "outside"):
            provider.get("vault-kv2:secret:another-team/credential")

    def test_azure_key_metadata_is_converted_to_standard_pem(self) -> None:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private.public_key().public_numbers()
        azure_key = SimpleNamespace(
            id="https://unit.vault.azure.net/keys/key/version",
            key=SimpleNamespace(
                n=numbers.n.to_bytes(256, "big"),
                e=numbers.e.to_bytes(3, "big"),
            ),
        )
        provider = AzureKeyVaultSigningProvider.__new__(AzureKeyVaultSigningProvider)
        provider.key_client = SimpleNamespace(get_key=lambda *_: azure_key)
        provider.key_name = "key"
        provider.key_version = "version"
        result = provider.active_key()
        self.assertEqual("RS256", result.algorithm)
        serialization.load_pem_public_key(result.public_pem.encode())

    def test_gcp_audit_refuses_unlocked_retention(self) -> None:
        bucket = SimpleNamespace(
            reload=lambda: None, retention_policy_locked=False,
            retention_period=86_400,
        )
        provider = GcpStorageAuditProvider.__new__(GcpStorageAuditProvider)
        provider.bucket_name = "audit"
        provider.bucket = bucket
        with self.assertRaisesRegex(ProviderError, "not locked"):
            provider.anchor(b"{}", 1)


if __name__ == "__main__":
    unittest.main()
