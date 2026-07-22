from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest

from vouchins_warden import RevokedError, WardenClient, __version__


class RecordingTransport:
    def __init__(self, status: int = 200, response=None):
        self.status = status
        self.response = response if response is not None else {"status": "ok"}
        self.calls = []
        self.content_type = "application/json"

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        return (
            self.status,
            {"X-Request-ID": "req-test", "Content-Type": self.content_type},
            (
                self.response.encode()
                if isinstance(self.response, str)
                else json.dumps(self.response).encode()
            ),
        )


class ClientTests(unittest.TestCase):
    def test_package_and_module_versions_match(self):
        metadata = tomllib.loads(
            (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["project"]["version"], __version__)

    def test_remote_plaintext_url_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            WardenClient("http://warden.example.com")

    def test_execute_adds_identity_and_unique_nonce(self):
        transport = RecordingTransport(
            response={"status": "executed", "tool_call_id": "call-1"}
        )
        client = WardenClient(
            "https://warden.example.com", access_token="oidc-token", transport=transport
        )
        kwargs = dict(
            capability_token="cap",
            runtime_proof="proof",
            task_id="task",
            connector_id="connector",
            action="issues.create",
            resource="repo://acme/app",
            environment="prod",
        )
        client.execute(**kwargs)
        client.execute(**kwargs)
        first = json.loads(transport.calls[0][3])
        second = json.loads(transport.calls[1][3])
        self.assertNotEqual(first["request_nonce"], second["request_nonce"])
        self.assertEqual("Bearer oidc-token", transport.calls[0][2]["Authorization"])

    def test_admin_key_is_sent_only_to_admin_methods(self):
        transport = RecordingTransport(response=[])
        client = WardenClient(
            "http://127.0.0.1:8000", admin_key="local-admin", transport=transport
        )
        client.agents()
        self.assertEqual("local-admin", transport.calls[0][2]["X-Admin-Key"])
        transport.response = {"status": "ok"}
        client.health()
        self.assertNotIn("X-Admin-Key", transport.calls[1][2])

    def test_structured_error_retains_request_id_without_credentials(self):
        transport = RecordingTransport(
            status=401,
            response={
                "error": {
                    "code": "revoked",
                    "detail": "API key is revoked",
                    "retryable": False,
                    "request_id": "req-body",
                }
            },
        )
        client = WardenClient(
            "https://warden.example.com",
            access_token="must-not-leak",
            transport=transport,
        )
        with self.assertRaises(RevokedError) as caught:
            client.health()
        self.assertEqual(401, caught.exception.status)
        self.assertEqual("req-body", caught.exception.request_id)
        self.assertEqual("revoked", caught.exception.code)
        self.assertNotIn("must-not-leak", str(caught.exception))

    def test_portal_resource_methods_use_authorized_endpoints(self):
        transport = RecordingTransport(response=[])
        client = WardenClient(
            "https://warden.example.com", admin_key="admin", transport=transport
        )
        client.apps.list()
        client.keys.list()
        client.approvals.list("approver@example.com")
        self.assertTrue(transport.calls[0][1].endswith("/admin/apps"))
        self.assertTrue(transport.calls[1][1].endswith("/admin/api-keys"))
        self.assertEqual("approver@example.com", transport.calls[2][2]["X-Approver-ID"])

    def test_csv_export_is_returned_as_text(self):
        transport = RecordingTransport(
            response="sequence,event_type\n1,action.executed\n"
        )
        transport.content_type = "text/csv"
        client = WardenClient("https://warden.example.com", transport=transport)
        self.assertIn("action.executed", client.audit_logs.export_csv(key_id="key-1"))


if __name__ == "__main__":
    unittest.main()
