import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

from fastapi.testclient import TestClient

from proxy.executor import DodoPaymentError
from proxy.main import app


class ProxyApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_health(self) -> None:
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_dashboard_is_served(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Warden", response.text)
        self.assertIn("Wispr Flow", response.text)
        self.assertIn("Tools used", response.text)
        self.assertIn("Dodo Payments", response.text)
        self.assertNotIn("Run comparison</button>", response.text)
        self.assertIn("execution starts after 2 seconds", response.text)
        self.assertIn('href="http://127.0.0.1:8080"', response.text)
        self.assertIn("Signed capability", response.text)
        self.assertIn("capability-chain", response.text)

    def test_audit_endpoint_only_returns_public_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            path.write_text(
                '{"timestamp":"2026-01-01T00:00:00Z","run_id":"abc","agent":"warden",'
                '"event":"scope_checked","allowed":false,"secret_ref":"hidden",'
                '"charge_id":"hidden"}\nnot-json\n',
                encoding="utf-8",
            )
            with patch("proxy.main.AUDIT_PATH", path):
                response = self.client.get("/audit/events")

        self.assertEqual(response.status_code, 200)
        event = response.json()["events"][0]
        self.assertFalse(event["allowed"])
        self.assertNotIn("secret_ref", event)
        self.assertNotIn("charge_id", event)

    @patch("proxy.main.classify_intent", return_value="FLIGHT_BOOKING")
    @patch("proxy.main._issue_and_delegate_capability", return_value=("token", "grant"))
    @patch("proxy.main.execute_booking")
    def test_demo_endpoint_infers_limit_and_reads_page_price(
        self, execute_booking, issue, _classify
    ) -> None:
        execute_booking.return_value = {
            "status": "blocked",
            "reason": "Requested ₹6000 exceeds authorized limit of ₹5000",
            "amount": 6000,
        }
        response = self.client.post(
            "/demo/bookings/execute",
            json={
                "instruction": "Book it. I authorize a maximum spend of ₹5,000.",
                "gate": "warden",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["amount"], 6000)
        self.assertEqual(response.json()["max_spend"], 5000)
        self.assertIn("audit_events", response.json())
        execute_booking.assert_called_once_with(
            6000.0,
            {"action": "confirm_booking", "max_spend": 5000.0},
            "dodo_payment_method",
            "token",
            "http://127.0.0.1:8080/",
        )
        issue.assert_called_once_with(5000.0, 300)

    @patch("proxy.main.classify_intent", return_value="FLIGHT_BOOKING")
    @patch("proxy.main.execute_booking_without_warden_demo")
    def test_unsafe_demo_requires_confirmation(self, unsafe_execute, _classify) -> None:
        response = self.client.post(
            "/demo/bookings/execute",
            json={
                "instruction": "Book it with a maximum spend of ₹5,000.",
                "gate": "without_warden",
                "confirm_unsafe_test_charge": False,
            },
        )
        self.assertEqual(response.status_code, 409)
        unsafe_execute.assert_not_called()

    @patch("proxy.main.execute_booking")
    @patch("proxy.main.classify_intent", return_value="OTHER")
    def test_unrelated_text_never_invokes_booking(self, _classify, execute_booking) -> None:
        response = self.client.post(
            "/demo/bookings/execute",
            json={"instruction": "What is the weather today?", "gate": "warden"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ignored")
        execute_booking.assert_not_called()

    @patch("proxy.main.execute_booking")
    def test_booking_endpoint_returns_blocked_result(self, execute_booking) -> None:
        execute_booking.return_value = {
            "status": "blocked",
            "reason": "Requested ₹6000 exceeds authorized limit of ₹5000",
            "amount": 6000,
        }

        response = self.client.post(
            "/bookings/execute",
            json={
                "amount": 6000,
                "scope": {"action": "confirm_booking", "max_spend": 5000},
                "capability_token": "token",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "blocked")
        execute_booking.assert_called_once_with(
            6000.0,
            {"action": "confirm_booking", "max_spend": 5000.0},
            "dodo_payment_method",
            "token",
            "http://127.0.0.1:8080/",
        )

    @patch("proxy.main.execute_booking", side_effect=DodoPaymentError("redacted"))
    def test_booking_endpoint_returns_sanitized_dodo_error(self, execute_booking) -> None:
        response = self.client.post(
            "/bookings/execute",
            json={
                "amount": 1000,
                "scope": {"action": "confirm_booking", "max_spend": 5000},
                "capability_token": "token",
            },
        )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json(), {"detail": "redacted"})

    def test_booking_endpoint_rejects_unknown_secret_ref(self) -> None:
        response = self.client.post(
            "/bookings/execute",
            json={
                "amount": 1000,
                "scope": {"action": "confirm_booking", "max_spend": 5000},
                "secret_ref": "some_other_secret",
                "capability_token": "token",
            },
        )

        self.assertEqual(response.status_code, 422)

    @patch("proxy.main._issue_and_delegate_capability", return_value=("token", "grant-id"))
    def test_capability_issue_endpoint(self, issue) -> None:
        response = self.client.post("/capabilities/issue", json={"max_spend": 5000})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"capability_token": "token", "grant_id": "grant-id"})
        issue.assert_called_once_with(5000.0, 300)


if __name__ == "__main__":
    unittest.main()
