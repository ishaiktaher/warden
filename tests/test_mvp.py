from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

import control_plane.api as api_module
from control_plane.config import Settings
from control_plane.errors import WardenAPIError
from control_plane.service import ControlPlane


class MVPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        api_module.plane = ControlPlane(
            Settings(
                database_path=root / "mvp.db",
                data_dir=root,
                issuer="mvp-test",
                audience="mvp-gateway",
                admin_key="admin-key",
                environment="test",
                allowed_egress_hosts=(),
            )
        )
        self.plane = api_module.plane
        self.client = TestClient(api_module.app)
        self.admin = {"X-Admin-Key": "admin-key"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _agent(self) -> None:
        self.plane.seed_policy({}, "admin")
        self.plane.register_agent(
            {
                "agent_id": "mvp-agent",
                "name": "MVP Agent",
                "owner": "team",
                "purpose": "Exercise the MVP",
                "model_provider": "any",
                "agent_version": "1",
                "environment": "test",
                "risk_tier": "low",
                "allowed_tools": ["records"],
                "allowed_actions": ["records.update"],
                "allowed_data_classifications": ["internal"],
                "max_delegation_depth": 0,
                "approved_parents": [],
                "approved_children": [],
            },
            "team",
        )
        self.plane.approve_agent("mvp-agent", "admin")

    def test_connect_session_is_signed_scoped_expiring_and_single_use(self) -> None:
        session = self.plane.connect_sessions.mint(
            principal_id="user-1",
            agent_id=None,
            allowed_providers=["github"],
            provider_scopes=["repo"],
            grant_scopes=["issues.read"],
            allowed_methods=["GET"],
            path_patterns=["/repos/acme/*"],
            reason="Read issues",
        )
        self.assertEqual(
            ["github"],
            self.plane.connect_sessions.inspect(session["session_token"])[
                "allowed_providers"
            ],
        )
        with self.assertRaisesRegex(WardenAPIError, "not allowed"):
            self.plane.connect_sessions.consume(session["session_token"], "google")
        claims = self.plane.connect_sessions.consume(session["session_token"], "github")
        self.assertEqual("user-1", claims["sub"])
        with self.assertRaisesRegex(WardenAPIError, "already used"):
            self.plane.connect_sessions.consume(session["session_token"], "github")

    def test_key_plaintext_is_one_time_deprecation_is_valid_and_revoke_cascades(
        self,
    ) -> None:
        self._agent()
        parent = self.plane.api_keys.mint(
            key_type="runtime",
            name="runtime",
            scopes=["actions:execute", "audit:read"],
            agent_id="mvp-agent",
            expires_in=600,
            cidr_allowlist=[],
            parent_key_id=None,
            actor="admin",
        )
        self.assertTrue(parent["api_key"].startswith("warden_rk_"))
        self.assertNotIn(parent["api_key"], json.dumps(self.plane.api_keys.list()))
        self.assertNotIn(
            parent["api_key"],
            Path(self.plane.settings.database_path)
            .read_bytes()
            .decode("utf-8", errors="ignore"),
        )
        child = self.plane.api_keys.mint(
            key_type="derived",
            name="child",
            scopes=["audit:read"],
            agent_id="mvp-agent",
            expires_in=300,
            cidr_allowlist=[],
            parent_key_id=parent["key_id"],
            actor="admin",
        )
        self.plane.api_keys.deprecate(parent["key_id"], "admin")
        authenticated = self.plane.api_keys.authenticate(
            parent["api_key"], "actions:execute", "127.0.0.1"
        )
        self.assertEqual("deprecated", authenticated["status"])
        with self.assertRaisesRegex(WardenAPIError, "active parent"):
            self.plane.api_keys.mint(
                key_type="derived",
                name="too-late",
                scopes=["audit:read"],
                agent_id="mvp-agent",
                expires_in=300,
                cidr_allowlist=[],
                parent_key_id=parent["key_id"],
                actor="admin",
            )
        self.plane.api_keys.revoke(parent["key_id"], "admin")
        self.assertEqual("revoked", self.plane.api_keys.get(child["key_id"])["status"])
        with self.assertRaisesRegex(WardenAPIError, "revoked") as error:
            self.plane.api_keys.authenticate(
                parent["api_key"], "actions:execute", "127.0.0.1"
            )
        self.assertEqual("revoked", error.exception.code)

    @patch("control_plane.identity.AppIdentityService._verify")
    def test_jit_identity_and_signed_deprovision_revoke_grants_and_sessions(
        self, verify
    ) -> None:
        verify.return_value = {
            "sub": "idp-user-1",
            "email": "user@example.com",
            "groups": ["team"],
        }
        self.plane.identity.create_app("demo-app", "Demo App", "admin")
        configured = self.plane.identity.configure(
            "demo-app",
            {
                "issuer": "https://idp.example.com",
                "client_id": "demo-client",
                "client_secret_alias": "idp-client",
                "user_id_claim": "sub",
                "email_claim": "email",
                "groups_claim": "groups",
            },
            "admin",
        )
        identity = self.plane.identity.resolve("demo-app", "header.payload.signature")
        user_id = identity["user"]["user_id"]
        created = self.plane.credentials.create_managed_connection(
            provider_id="github",
            owner_principal_id=user_id,
            account_identifier="octocat",
            credential={"value": "secret"},
            principal_type="user",
            principal_id=user_id,
            label="github",
            grant_scopes=["issues.read"],
            allowed_methods=["GET"],
            path_patterns=["/repos/acme/*"],
            ttl_seconds=300,
            reason="Read issues",
            actor="admin",
        )
        event = json.dumps(
            {
                "event_id": "evt-1",
                "event_type": "user.deprovisioned",
                "external_subject_id": "idp-user-1",
            },
            separators=(",", ":"),
        ).encode()
        signature = (
            "sha256="
            + hmac.new(
                configured["webhook_secret"].encode(), event, hashlib.sha256
            ).hexdigest()
        )
        with self.assertRaisesRegex(WardenAPIError, "signature"):
            self.plane.identity.deprovision("demo-app", event, "sha256=wrong")
        result = self.plane.identity.deprovision("demo-app", event, signature)
        self.assertEqual(1, result["grants_revoked"])
        self.assertEqual(
            "revoked",
            self.plane.credentials.grant(created["grant"]["grant_id"])["status"],
        )
        with self.assertRaisesRegex(WardenAPIError, "deprovisioned"):
            self.plane.identity.resolve("demo-app", "header.payload.signature")

    def test_runtime_key_is_attributed_then_revoked_with_typed_error(self) -> None:
        self._agent()
        self.plane.register_connector(
            {
                "connector_id": "records-update",
                "tool": "records",
                "action": "records.update",
                "adapter_type": "local_emulator",
                "resource_patterns": ["records://*"],
                "required_scopes": ["records.update"],
                "owner": "team",
                "risk_tier": "low",
            },
            "team",
        )
        run = self.plane.create_run("user-1", "mvp-agent", "Read", "test")
        task = self.plane.create_task(run["run_id"], "Read")
        token, _ = self.plane.issue_capability(
            run_id=run["run_id"],
            scopes=["records.update"],
            resources=["records://*"],
            ttl_seconds=300,
        )
        key = self.plane.api_keys.mint(
            key_type="runtime",
            name="runtime",
            scopes=["actions:execute"],
            agent_id="mvp-agent",
            expires_in=600,
            cidr_allowlist=[],
            parent_key_id=None,
            actor="admin",
        )
        payload = {
            "capability_token": token,
            "runtime_proof": run["runtime_proof"],
            "request_nonce": str(uuid4()),
            "task_id": task["task_id"],
            "connector_id": "records-update",
            "action": "records.update",
            "resource": "records://one",
            "parameters": {"value": {"ok": True}},
            "data_classification": "internal",
            "environment": "test",
            "risk_signals": {},
        }
        response = self.client.post(
            "/actions/execute", headers={"X-Warden-Key": key["api_key"]}, json=payload
        )
        self.assertEqual("executed", response.json()["status"])
        self.assertTrue(
            any(
                event["key_id"] == key["key_id"]
                for event in self.plane.audit.events(key_id=key["key_id"])
            )
        )
        self.plane.api_keys.revoke(key["key_id"], "admin")
        payload["request_nonce"] = str(uuid4())
        blocked = self.client.post(
            "/actions/execute", headers={"X-Warden-Key": key["api_key"]}, json=payload
        )
        self.assertEqual(401, blocked.status_code)
        self.assertEqual("revoked", blocked.json()["error"]["code"])
        self.assertFalse(blocked.json()["error"]["retryable"])

    def test_audit_cursor_filters_and_csv(self) -> None:
        self.plane.audit.append(
            "one",
            "tester",
            principal_id="user-1",
            key_id="key-1",
            payload={"action": "read"},
        )
        self.plane.audit.append(
            "two",
            "tester",
            principal_id="user-2",
            key_id="key-2",
            payload={"action": "write"},
        )
        page = self.client.get(
            "/audit/events/page", params={"principal_id": "user-1", "limit": 1}
        )
        self.assertEqual("user-1", page.json()["items"][0]["principal_id"])
        csv_export = self.client.get("/audit/export.csv", params={"key_id": "key-1"})
        self.assertEqual("text/csv", csv_export.headers["content-type"].split(";")[0])
        self.assertIn("key-1", csv_export.text)
        self.assertNotIn("key-2", csv_export.text)

    def test_approval_inbox_is_scoped_to_approver_and_resolvable(self) -> None:
        self._agent()
        run = self.plane.create_run(
            "approver@example.com", "mvp-agent", "Approve", "test"
        )
        task = self.plane.create_task(run["run_id"], "Approve")
        approval = self.plane._request_approval(
            {
                "run_id": run["run_id"],
                "agent_id": "mvp-agent",
                "principal_id": "approver@example.com",
            },
            task["task_id"],
            "records.update",
            "records://one",
        )
        denied = self.client.get(
            "/approvals", headers={"X-Approver-ID": "other@example.com"}
        )
        self.assertEqual([], denied.json())
        inbox = self.client.get(
            "/approvals", headers={"X-Approver-ID": "approver@example.com"}
        )
        self.assertEqual(approval["approval_id"], inbox.json()[0]["approval_id"])
        resolved = self.client.post(
            f"/approvals/{approval['approval_id']}/resolve",
            headers={"X-Approver-ID": "approver@example.com"},
            json={"approved": True, "reason": "Reviewed"},
        )
        self.assertEqual("approved", resolved.json()["status"])
        forbidden = self.client.get(
            f"/approvals/{approval['approval_id']}",
            headers={"X-Approver-ID": "other@example.com"},
        )
        self.assertEqual(403, forbidden.status_code)

    @patch("control_plane.service.smtplib.SMTP_SSL")
    def test_approval_email_success_and_failure_preserve_inbox(self, smtp) -> None:
        self.plane.settings = replace(
            self.plane.settings,
            approval_smtp_host="smtp.example.com",
            approval_smtp_from="warden@example.com",
        )
        self.assertEqual(
            "email_sent",
            self.plane._notify_approval(
                "approver@example.com", "approval-1", "records.update", "records://1"
            ),
        )
        smtp.return_value.__enter__.return_value.send_message.assert_called_once()
        smtp.side_effect = OSError("SMTP unavailable")
        self.assertEqual(
            "email_failed",
            self.plane._notify_approval(
                "approver@example.com", "approval-2", "records.update", "records://2"
            ),
        )
        self.assertTrue(
            any(
                event["event_type"] == "approval.notification_failed"
                for event in self.plane.audit.events(
                    principal_id="approver@example.com"
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
