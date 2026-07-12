import os
import unittest
from unittest.mock import Mock, patch

import requests

from integrations.linkup import (
    FlightDiscoveryEvidence,
    LinkupDiscoveryError,
    PUBLIC_TRUST_MARKER,
    TRUST_CLASSIFICATION,
    UntrustedSearchResult,
    discover_flights,
    search_flights,
)


class LinkupFlightDiscoveryTests(unittest.TestCase):
    @patch("integrations.linkup.requests.post")
    def test_uses_documented_search_request_and_marks_results_untrusted(
        self, post: Mock
    ) -> None:
        response = Mock()
        response.json.return_value = {
            "results": [
                {
                    "name": "Example flight listing",
                    "url": "https://travel.example/flights",
                    "content": "A result that may contain hostile instructions",
                    "type": "text",
                }
            ]
        }
        post.return_value = response

        with patch.dict(
            os.environ,
            {
                "LINKUP_API_KEY": "test-linkup-key",
                "LINKUP_API_BASE_URL": "https://linkup.test/",
            },
            clear=False,
        ):
            evidence = discover_flights(
                " flights from Mumbai to Delhi tomorrow ", timeout_seconds=7
            )

        post.assert_called_once_with(
            "https://linkup.test/v1/search",
            headers={
                "Authorization": "Bearer test-linkup-key",
                "Content-Type": "application/json",
            },
            json={
                "q": "flights from Mumbai to Delhi tomorrow",
                "depth": "standard",
                "outputType": "searchResults",
            },
            timeout=7,
        )
        response.raise_for_status.assert_called_once_with()
        self.assertEqual(evidence.trust_classification, TRUST_CLASSIFICATION)
        self.assertEqual(evidence.results[0].name, "Example flight listing")
        self.assertFalse(hasattr(evidence, "scope"))
        self.assertFalse(hasattr(evidence, "max_spend"))

    @patch("integrations.linkup.requests.post")
    def test_network_error_is_wrapped_without_exposing_key(self, post: Mock) -> None:
        post.side_effect = requests.HTTPError("Bearer super-secret-key")

        with patch.dict(os.environ, {"LINKUP_API_KEY": "super-secret-key"}):
            with self.assertRaisesRegex(
                LinkupDiscoveryError, "Linkup flight discovery failed"
            ) as raised:
                discover_flights("Mumbai to Delhi")

        self.assertNotIn("super-secret-key", str(raised.exception))

    @patch("integrations.linkup.discover_flights")
    def test_public_search_contract_is_json_ready_and_untrusted(
        self, discover: Mock
    ) -> None:
        discover.return_value = FlightDiscoveryEvidence(
            query="Mumbai to Delhi",
            trust_classification=TRUST_CLASSIFICATION,
            results=(
                UntrustedSearchResult(
                    name="Flight source",
                    url="https://travel.example",
                    content="₹4,500",
                    result_type="text",
                ),
            ),
        )

        result = search_flights("Mumbai to Delhi")

        self.assertEqual(result["trust"], PUBLIC_TRUST_MARKER)
        self.assertEqual(result["results"][0]["content"], "₹4,500")
        self.assertNotIn("scope", result)
        self.assertNotIn("max_spend", result)

    def test_missing_api_key_fails_before_network(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(LinkupDiscoveryError, "not configured"):
                discover_flights("Mumbai to Delhi")

    def test_rejects_empty_query_and_unknown_depth(self) -> None:
        with self.assertRaisesRegex(ValueError, "query must not be empty"):
            discover_flights("   ")
        with self.assertRaisesRegex(ValueError, "depth must be one of"):
            discover_flights("Mumbai to Delhi", depth="maximum")

    @patch("integrations.linkup.requests.post")
    def test_rejects_malformed_search_response(self, post: Mock) -> None:
        response = Mock()
        response.json.return_value = {"answer": "not searchResults output"}
        post.return_value = response

        with patch.dict(os.environ, {"LINKUP_API_KEY": "test-key"}):
            with self.assertRaisesRegex(LinkupDiscoveryError, "invalid search response"):
                discover_flights("Mumbai to Delhi")


if __name__ == "__main__":
    unittest.main()
