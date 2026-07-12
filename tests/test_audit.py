import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit import record_audit_event


class AuditTrailTests(unittest.TestCase):
    def test_appends_sanitized_correlated_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"HERMES_SESSION_ID": "private-session-value"}
        ):
            path = Path(directory) / "audit.jsonl"
            first = record_audit_event(
                "discovery_agent",
                "discovery_completed",
                {"status": "success", "result_count": 2, "trust": "untrusted_external_evidence"},
                path=path,
            )
            record_audit_event(
                "warden", "scope_checked", {"allowed": False, "amount": 6000, "max_spend": 5000}, path=path
            )
            rows = [json.loads(line) for line in path.read_text().splitlines()]

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["run_id"], rows[1]["run_id"])
        self.assertNotEqual(first["run_id"], "private-session-value")

    def test_rejects_secret_or_arbitrary_metadata(self) -> None:
        for unsafe in ("charge_id", "subscription_id", "secret_ref", "prompt", "token"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                record_audit_event("booking_agent", "booking_completed", {unsafe: "do-not-log"})

    def test_capability_event_accepts_safe_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = record_audit_event(
                "warden",
                "capability_rejected",
                {
                    "status": "blocked",
                    "grant_id": "123e4567-e89b-12d3-a456-426614174000",
                    "reason": "Capability already consumed",
                },
                path=Path(directory) / "audit.jsonl",
            )
        self.assertEqual(record["reason"], "Capability already consumed")
        self.assertNotIn("token", record)

    def test_rejects_unknown_agent_and_event(self) -> None:
        with self.assertRaises(ValueError):
            record_audit_event("mystery_agent", "booking_completed")
        with self.assertRaises(ValueError):
            record_audit_event("booking_agent", "arbitrary_event")


if __name__ == "__main__":
    unittest.main()
