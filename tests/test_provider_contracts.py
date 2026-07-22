from __future__ import annotations

import unittest
from urllib.parse import urlparse

from control_plane.integrations import PROVIDER_CONTRACTS, catalog


class ProviderContractTests(unittest.TestCase):
    def test_exact_mvp_oauth_contract_set_is_safe_and_complete(self) -> None:
        self.assertEqual(
            {"github", "google", "slack", "notion", "stripe"}, set(PROVIDER_CONTRACTS)
        )
        required = {
            "authorization_url",
            "token_url",
            "api_base_url",
            "identity_url",
            "identity_id_field",
            "identity_label_field",
        }
        for provider, contract in PROVIDER_CONTRACTS.items():
            self.assertEqual(required, set(contract), provider)
            for field in (
                "authorization_url",
                "token_url",
                "api_base_url",
                "identity_url",
            ):
                parsed = urlparse(contract[field])
                self.assertEqual("https", parsed.scheme, f"{provider}.{field}")
                self.assertTrue(parsed.hostname, f"{provider}.{field}")

    def test_only_mvp_set_was_promoted_from_catalog_only_by_this_contract(self) -> None:
        verified_oauth = {
            item["integration_id"].split(":", 1)[1]
            for item in catalog(kind="oauth2")
            if item["verification"] == "contract_tested"
        }
        self.assertEqual(set(PROVIDER_CONTRACTS), verified_oauth)


if __name__ == "__main__":
    unittest.main()
