"""Opt-in conformance test for the actually configured infrastructure providers.

Run only against an isolated test account:
WARDEN_RUN_LIVE_PROVIDER_TESTS=1 python -m unittest tests.test_provider_live -v
"""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from control_plane.config import load_settings
from control_plane.providers import audit_provider, secrets_provider, signing_provider


@unittest.skipUnless(
    os.getenv("WARDEN_RUN_LIVE_PROVIDER_TESTS") == "1",
    "live provider conformance is explicitly opt-in",
)
class LiveProviderConformanceTests(unittest.TestCase):
    def test_selected_provider_pack(self) -> None:
        configured = load_settings()

        signer = signing_provider(configured)
        self.assertIsNotNone(signer)
        key = signer.active_key()  # type: ignore[union-attr]
        message = b"warden-provider-conformance"
        signature = signer.sign(key.key_id, message)  # type: ignore[union-attr]
        public = serialization.load_pem_public_key(key.public_pem.encode())
        public.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]

        secrets = secrets_provider(configured)
        self.assertIsNotNone(secrets)
        expected = "conformance-" + uuid4().hex
        reference = secrets.put("conformance/" + uuid4().hex, expected)  # type: ignore[union-attr]
        try:
            self.assertEqual(expected, secrets.get(reference))  # type: ignore[union-attr]
        finally:
            secrets.revoke(reference)  # type: ignore[union-attr]

        audit = audit_provider(configured)
        self.assertIsNotNone(audit)
        receipt = audit.anchor(b'{"conformance":true}', retention_days=1)  # type: ignore[union-attr]
        self.assertIsInstance(receipt, dict)


if __name__ == "__main__":
    unittest.main()
