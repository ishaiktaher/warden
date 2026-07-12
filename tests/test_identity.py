import os
import unittest
from unittest.mock import Mock, patch

from identity.capability import _consume_grant, issue_capability, verify_capability
from identity.registry import AGENT_REGISTRY, get_agent


RESOURCE = "http://127.0.0.1:8080/"


class IdentityRegistryTests(unittest.TestCase):
    def test_registry_has_four_stable_agents(self) -> None:
        self.assertEqual(
            set(AGENT_REGISTRY),
            {"orchestrator", "discovery", "booking", "communication"},
        )
        self.assertEqual(get_agent("booking").agent_id, "booking")


@patch.dict(os.environ, {"CAPABILITY_SIGNING_KEY": "unit-test-signing-key"})
@patch("identity.capability.record_audit_event")
class CapabilityTests(unittest.TestCase):
    def test_consumption_uses_atomic_ignore_duplicate_upsert(self, _audit) -> None:
        response = type("Response", (), {"data": [{"grant_id": "grant"}]})()
        query = Mock()
        query.execute.return_value = response
        table = Mock()
        table.upsert.return_value = query
        client = Mock()
        client.table.return_value = table
        with patch("identity.capability._supabase_client", return_value=client):
            self.assertTrue(_consume_grant("grant"))
        client.table.assert_called_once_with("consumed_grants")
        table.upsert.assert_called_once_with(
            {"grant_id": "grant"},
            on_conflict="grant_id",
            ignore_duplicates=True,
        )

    def test_valid_capability_is_atomically_consumed(self, _audit) -> None:
        token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
        with patch("identity.capability._consume_grant", return_value=True) as consume:
            result = verify_capability(token, "booking", "confirm_booking", RESOURCE)
        self.assertTrue(result.valid)
        self.assertEqual(result.reason, "Capability verified")
        consume.assert_called_once_with(result.grant_id)

    def test_replay_is_rejected(self, _audit) -> None:
        token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
        with patch("identity.capability._consume_grant", side_effect=[True, False]):
            first = verify_capability(token, "booking", "confirm_booking", RESOURCE)
            second = verify_capability(token, "booking", "confirm_booking", RESOURCE)
        self.assertTrue(first.valid)
        self.assertFalse(second.valid)
        self.assertEqual(second.reason, "Capability already consumed")

    def test_expired_short_circuits_before_consumption(self, _audit) -> None:
        with patch("identity.capability.time.time", return_value=1000):
            token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 1)
        with patch("identity.capability.time.time", return_value=1002), patch(
            "identity.capability._consume_grant"
        ) as consume:
            result = verify_capability(token, "booking", "confirm_booking", RESOURCE)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "Capability expired")
        consume.assert_not_called()

    def test_claim_mismatch_order_and_tamper(self, _audit) -> None:
        token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
        tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        self.assertEqual(
            verify_capability(tampered, "booking", "confirm_booking", RESOURCE).reason,
            "Invalid capability signature",
        )
        self.assertEqual(
            verify_capability(token, "orchestrator", "other", "wrong").reason,
            "Capability agent identity mismatch",
        )
        self.assertEqual(
            verify_capability(token, "booking", "other", "wrong").reason,
            "Capability action mismatch",
        )
        self.assertEqual(
            verify_capability(token, "booking", "confirm_booking", "wrong").reason,
            "Capability resource mismatch",
        )


if __name__ == "__main__":
    unittest.main()
