from __future__ import annotations

import tempfile
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from control_plane.config import Settings
from control_plane.providers import ProviderError, SigningKey, signing_provider
from control_plane.service import ControlPlane


class FakeSigner:
    name = "fake-kms"
    def __init__(self) -> None:
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def active_key(self) -> SigningKey:
        public = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return SigningKey("fake-key-v1", "RS256", public)

    def sign(self, key_id: str, message: bytes) -> bytes:
        if key_id != "fake-key-v1":
            raise RuntimeError("unexpected key")
        return self.private.sign(message, padding.PKCS1v15(), hashes.SHA256())


class FakeSecrets:
    name = "fake-vault"
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def put(self, name: str, value: str) -> str:
        reference = f"vault://{name}"
        self.values[reference] = value
        return reference

    def get(self, reference: str) -> str:
        return self.values[reference]

    def revoke(self, reference: str) -> None:
        self.values.pop(reference, None)


class FakeAudit:
    name = "fake-worm"
    def anchor(self, document: bytes, retention_days: int) -> dict:
        return {"receipt_id": "receipt-1", "bytes": len(document), "retention_days": retention_days}


SIGNER = FakeSigner()
SECRETS = FakeSecrets()
AUDIT = FakeAudit()


def signing_factory(settings: Settings) -> FakeSigner:
    del settings
    return SIGNER


def secrets_factory(settings: Settings) -> FakeSecrets:
    del settings
    return SECRETS


def audit_factory(settings: Settings) -> FakeAudit:
    del settings
    return AUDIT


class ProviderPortTests(unittest.TestCase):
    def test_local_custody_is_rejected_in_production(self) -> None:
        settings = Settings(
            database_path=Path("unused"), data_dir=Path("unused"),
            issuer="test", audience="test", admin_key="test",
            environment="prod", allowed_egress_hosts=(),
        )
        with self.assertRaisesRegex(ProviderError, "forbidden in production"):
            signing_provider(settings)

    def test_custom_providers_run_without_cloud_specific_core_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plane = ControlPlane(Settings(
                database_path=root / "providers.db", data_dir=root,
                issuer="provider-test", audience="provider-gateway",
                admin_key="admin", environment="test", allowed_egress_hosts=(),
                signing_provider="tests.test_providers:signing_factory",
                secrets_provider="tests.test_providers:secrets_factory",
                audit_provider="tests.test_providers:audit_factory",
            ))
            plane.register_agent({
                "agent_id": "portable-agent", "name": "Portable Agent", "owner": "team",
                "purpose": "Prove portable custody", "model_provider": "any",
                "agent_version": "1", "environment": "test", "risk_tier": "low",
                "allowed_tools": ["records"], "allowed_actions": ["records.read"],
                "allowed_data_classifications": ["internal"], "max_delegation_depth": 0,
            }, "team")
            plane.approve_agent("portable-agent", "admin")
            run = plane.create_run("human", "portable-agent", "Read", "test")
            token, claims = plane.issue_capability(
                run_id=run["run_id"], scopes=["records.read"],
                resources=["records://item/1"], ttl_seconds=60,
            )
            self.assertEqual(claims["jti"], plane.capabilities.verify(token)["jti"])
            key = plane.database.one("SELECT algorithm,private_pem FROM signing_keys WHERE status='active'")
            self.assertEqual("EXTERNAL_RS256", key["algorithm"])
            self.assertEqual("", key["private_pem"])

            plane.secrets.store("connector-key", "portable-secret", "admin")
            resolved = plane.secrets.resolve_for_connector(
                "connector-key", connector_id="records", run_id=run["run_id"],
                task_id="task", tool_call_id="call",
            )
            self.assertEqual("portable-secret", resolved)
            anchored = plane.audit.anchor("admin", retention_days=30)
            self.assertEqual("fake-worm", anchored["provider"])
            self.assertEqual("receipt-1", anchored["receipt"]["receipt_id"])


if __name__ == "__main__":
    unittest.main()
