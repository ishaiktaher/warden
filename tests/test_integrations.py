from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from control_plane.api import app
from control_plane.integrations import INTEGRATIONS, catalog, catalog_summary


class IntegrationCatalogTests(unittest.TestCase):
    def test_catalog_has_over_one_hundred_unique_provider_modes(self) -> None:
        summary = catalog_summary()
        self.assertGreaterEqual(summary["total"], 100)
        self.assertGreater(summary["oauth2"], 0)
        self.assertGreater(summary["managed_secret"], 0)
        self.assertEqual(len(INTEGRATIONS), len({item.integration_id for item in INTEGRATIONS}))
        self.assertTrue(summary["custom_providers_supported"])
        self.assertEqual(3, summary["contract_tested"])
        self.assertEqual(0, summary["live_verified"])

    def test_overlapping_vendors_keep_oauth_and_managed_modes_separate(self) -> None:
        ids = {item["integration_id"] for item in catalog(query="github")}
        self.assertEqual(ids, {"oauth:github", "managed:github"})

    def test_catalog_api_is_public_and_filterable(self) -> None:
        client = TestClient(app)
        response = client.get("/integrations", params={"kind": "managed_secret", "query": "AWS"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["integration_id"], "managed:aws")

    def test_catalog_distinguishes_listing_from_verification(self) -> None:
        verified = {
            item["integration_id"] for item in catalog()
            if item["verification"] == "contract_tested"
        }
        self.assertEqual(
            {"oauth:github", "managed:slack", "managed:vouchins-admin-api"},
            verified,
        )
        evidence = [
            item["evidence"] for item in catalog()
            if item["verification"] == "contract_tested"
        ]
        self.assertTrue(all(evidence))


if __name__ == "__main__":
    unittest.main()
