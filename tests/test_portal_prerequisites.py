from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import hashlib
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

import control_plane.api as api_module
from control_plane.config import Settings
from control_plane.service import ControlPlane


class PortalPrerequisiteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        api_module.plane = ControlPlane(
            Settings(
                database_path=root / "portal.db",
                data_dir=root,
                issuer="portal-test",
                audience="portal-gateway",
                admin_key="admin-key",
                environment="test",
                allowed_egress_hosts=(),
                public_url="https://testserver",
            )
        )
        self.plane = api_module.plane
        self.client = TestClient(api_module.app, base_url="https://testserver")
        self.admin = {"X-Admin-Key": "admin-key"}
        self.plane.secrets.store("portal-client", "client-secret", "admin")
        self.plane.identity.create_app("portal-app", "Portal", "control-plane-admin")
        self.plane.identity.configure(
            "portal-app",
            {
                "issuer": "https://idp.example.com",
                "client_id": "portal-client",
                "client_secret_alias": "portal-client",
                "user_id_claim": "sub",
                "email_claim": "email",
                "groups_claim": "groups",
            },
            "admin",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _discovery() -> Mock:
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
        }
        return response

    def _gateway_request(self, *, deny: bool = False) -> dict:
        self.plane.seed_policy(
            {"deny_actions": ["records.update"] if deny else []}, "admin"
        )
        self.plane.register_agent(
            {
                "agent_id": "trace-agent",
                "name": "Trace Agent",
                "owner": "team",
                "purpose": "Test enforcement tracing",
                "model_provider": "test",
                "agent_version": "1",
                "environment": "test",
                "risk_tier": "low",
                "allowed_tools": ["records"],
                "allowed_actions": ["records.update"],
                "allowed_data_classifications": ["internal"],
                "max_delegation_depth": 0,
            },
            "team",
        )
        self.plane.approve_agent("trace-agent", "admin")
        self.plane.register_connector(
            {
                "connector_id": "trace-connector",
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
        run = self.plane.create_run("user-1", "trace-agent", "Trace", "test")
        task = self.plane.create_task(run["run_id"], "Trace")
        token, _ = self.plane.issue_capability(
            run_id=run["run_id"],
            scopes=["records.update"],
            resources=["records://*"],
            ttl_seconds=300,
        )
        return self.plane.execute_action(
            token=token,
            runtime_proof=run["runtime_proof"],
            request_nonce=str(uuid4()),
            task_id=task["task_id"],
            connector_id="trace-connector",
            action="records.update",
            resource="records://one",
            parameters={"value": {"ok": True}},
            data_classification="internal",
            environment="test",
        )

    @patch("control_plane.identity.AppIdentityService._verify")
    @patch("control_plane.identity.requests.post")
    @patch("control_plane.identity.requests.get")
    def _login(self, get: Mock, post: Mock, verify: Mock) -> tuple[str, str]:
        get.return_value = self._discovery()
        token = Mock()
        token.raise_for_status.return_value = None
        token.json.return_value = {"id_token": "header.payload.signature"}
        post.return_value = token
        verify.return_value = {
            "sub": "subject-1",
            "email": "admin@example.com",
            "groups": ["admins"],
        }
        started = self.client.get(
            "/portal/auth/login/portal-app", follow_redirects=False
        )
        self.assertEqual(302, started.status_code)
        state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
        verify.return_value["nonce"] = self.plane.database.one(
            "SELECT nonce FROM browser_oidc_states WHERE state_hash=?",
            (hashlib.sha256(state.encode()).hexdigest(),),
        )["nonce"]
        completed = self.client.get(
            "/portal/auth/callback",
            params={"state": state, "code": "authorization-code"},
            follow_redirects=False,
        )
        self.assertEqual(303, completed.status_code)
        return state, self.client.cookies["warden_csrf"]

    def test_login_replay_logout_and_server_side_invalidation(self) -> None:
        state, csrf = self._login()
        session = self.client.get("/portal/session")
        self.assertEqual("admin@example.com", session.json()["email"])
        replay = self.client.get(
            "/portal/auth/callback",
            params={"state": state, "code": "again"},
            follow_redirects=False,
        )
        self.assertEqual(401, replay.status_code)
        self.assertEqual("unauthorized", replay.json()["error"]["code"])
        missing_csrf = self.client.post("/portal/logout")
        self.assertEqual(403, missing_csrf.status_code)
        logged_out = self.client.post("/portal/logout", headers={"X-CSRF-Token": csrf})
        self.assertEqual(200, logged_out.status_code)
        token_hash = self.plane.database.one(
            "SELECT status FROM user_sessions ORDER BY created_at DESC LIMIT 1"
        )
        self.assertEqual("revoked", token_hash["status"])

    def test_wus_session_is_principal_bound_and_revocation_is_typed(self) -> None:
        self._login()
        session_token = self.client.cookies["warden_session"]
        user = self.plane.database.one(
            "SELECT user_id FROM app_users WHERE external_subject_id='subject-1'"
        )
        result = self.client.get(
            "/me/connections",
            params={"principal_id": "someone-else"},
            headers={"Authorization": f"Bearer {session_token}"},
        )
        self.assertEqual([], result.json())
        self.plane.database.execute(
            "UPDATE user_sessions SET status='revoked' WHERE user_id=?",
            (user["user_id"],),
        )
        rejected = self.client.get(
            "/me/connections", headers={"Authorization": f"Bearer {session_token}"}
        )
        self.assertEqual(401, rejected.status_code)
        self.assertEqual("revoked", rejected.json()["error"]["code"])

    def test_expired_and_tampered_wus_sessions_are_typed(self) -> None:
        self._login()
        session_token = self.client.cookies["warden_session"]
        self.plane.database.execute(
            "UPDATE user_sessions SET expires_at=?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
        )
        expired = self.client.get(
            "/me/grants", headers={"Authorization": f"Bearer {session_token}"}
        )
        self.assertEqual("expired_session", expired.json()["error"]["code"])
        tampered = self.client.get(
            "/me/grants", headers={"Authorization": "Bearer wus_tampered"}
        )
        self.assertEqual("unauthorized", tampered.json()["error"]["code"])

    def test_app_reads_are_owner_scoped_and_secrets_are_redacted(self) -> None:
        self.plane.identity.create_app("other-app", "Other", "other-owner")
        listed = self.client.get("/admin/apps", headers=self.admin)
        self.assertEqual(["portal-app"], [item["app_id"] for item in listed.json()])
        identity = self.client.get(
            "/admin/apps/portal-app/identity", headers=self.admin
        )
        self.assertEqual("portal-client", identity.json()["client_id"])
        self.assertNotIn("client_secret", identity.text)
        users = self.client.get("/admin/apps/portal-app/users", headers=self.admin)
        self.assertEqual([], users.json())
        foreign = self.client.get("/admin/apps/other-app/users", headers=self.admin)
        self.assertEqual(404, foreign.status_code)

    def test_production_entrypoint_has_no_development_provider_routes(self) -> None:
        response = self.client.get(
            "/_dev/mock/github/authorize",
            params={
                "redirect_uri": "https://testserver/oauth/github/callback",
                "state": "x",
            },
            follow_redirects=False,
        )
        self.assertEqual(404, response.status_code)

    def test_development_github_connect_is_end_to_end_and_labeled_synthetic(
        self,
    ) -> None:
        from control_plane.dev_portal import create_dev_app

        dev_client = TestClient(create_dev_app(), base_url="https://testserver")
        self.plane.secrets.store("github-client", "synthetic-secret", "admin")
        configured = dev_client.post(
            "/admin/oauth/providers/github",
            headers=self.admin,
            json={
                "provider_id": "github",
                "client_id": "synthetic-client",
                "client_secret_alias": "github-client",
                "authorization_url": "https://testserver/_dev/mock/github/authorize",
                "token_url": "https://testserver/_dev/mock/github/token",
                "api_base_url": "https://testserver/_dev/mock/github",
                "identity_url": "https://testserver/_dev/mock/github/user",
                "identity_id_field": "id",
                "identity_label_field": "login",
                "scope_separator": " ",
                "default_scopes": ["repo"],
            },
        )
        self.assertEqual(200, configured.status_code)
        session = dev_client.post(
            "/admin/connect/sessions",
            headers=self.admin,
            json={
                "principal_id": "portal-user",
                "allowed_providers": ["github"],
                "provider_scopes": ["repo"],
                "grant_scopes": ["issues.create"],
                "allowed_methods": ["POST"],
                "path_patterns": ["/repos/acme/app/issues"],
                "reason": "Portal test",
            },
        ).json()
        started = dev_client.post(
            "/connect/github/start", json={"session_token": session["session_token"]}
        ).json()
        authorized = dev_client.get(started["connect_url"], follow_redirects=False)
        self.assertEqual(307, authorized.status_code)
        completed = dev_client.get(
            authorized.headers["location"],
            headers={"Accept": "application/json"},
        )
        self.assertEqual("connected", completed.json()["status"])
        self.assertTrue(
            any(
                event["payload"].get("synthetic") is True
                for event in self.plane.audit.events(
                    event_type="dev.mock_provider_response"
                )
            )
        )

    def test_successful_enforcement_trace_has_all_stages_in_order(self) -> None:
        result = self._gateway_request()
        trace = self.client.get(f"/enforcement-traces/{result['tool_call_id']}").json()
        core = [
            item
            for item in trace["stages"]
            if not item["stage"].startswith("policy_layer:")
        ]
        self.assertEqual(
            [name for _, name in self.plane.TRACE_STAGES],
            [item["stage"] for item in core],
        )
        self.assertTrue(all(item["status"] == "passed" for item in core))

    def test_policy_denial_trace_skips_later_stages_without_fabrication(self) -> None:
        result = self._gateway_request(deny=True)
        trace = self.plane.enforcement_trace(result["tool_call_id"])
        stages = {item["stage"]: item for item in trace["stages"]}
        self.assertEqual("failed", stages["policy_layers"]["status"])
        for name in (
            "approval_gate",
            "credential_resolution",
            "connector_dispatch",
        ):
            self.assertEqual("skipped", stages[name]["status"])

    def test_uninstrumented_trace_stage_is_explicitly_unrecorded(self) -> None:
        call_id = str(uuid4())
        self.plane._start_trace(call_id)
        trace = self.plane.enforcement_trace(call_id)
        self.assertTrue(all(item["status"] == "unrecorded" for item in trace["stages"]))

    def test_portal_gateway_approval_resume_revoke_and_trace_loop(self) -> None:
        self.plane.seed_policy({}, "admin")
        self.plane.register_agent(
            {
                "agent_id": "github-agent",
                "name": "GitHub Agent",
                "owner": "team",
                "purpose": "Portal vertical slice",
                "model_provider": "test",
                "agent_version": "1",
                "environment": "test",
                "risk_tier": "low",
                "allowed_tools": ["github"],
                "allowed_actions": ["issues.create"],
                "allowed_data_classifications": ["internal"],
                "max_delegation_depth": 0,
            },
            "team",
        )
        self.plane.approve_agent("github-agent", "admin")
        self.plane.register_connector(
            {
                "connector_id": "portal-github",
                "tool": "github",
                "action": "issues.create",
                "adapter_type": "local_emulator",
                "endpoint": "https://api.github.com/repos/acme/app/issues",
                "http_method": "POST",
                "resource_patterns": ["github://repos/acme/*"],
                "required_scopes": ["issues.create"],
                "owner": "team",
                "risk_tier": "high",
                "grant_required": True,
            },
            "team",
        )
        connection = self.plane.credentials.create_managed_connection(
            provider_id="github",
            owner_principal_id="user-1",
            account_identifier="synthetic-octocat",
            credential={"value": "synthetic-token"},
            principal_type="user",
            principal_id="user-1",
            label="portal",
            grant_scopes=["issues.create"],
            allowed_methods=["POST"],
            path_patterns=["/repos/acme/app/issues"],
            ttl_seconds=600,
            reason="Portal test",
            actor="admin",
        )
        grant_id = connection["grant"]["grant_id"]
        self.plane.credentials.delegate_grant(
            grant_id, "github-agent", "user-1", "Portal test"
        )
        run = self.plane.create_run("user-1", "github-agent", "Portal", "test")
        task = self.plane.create_task(run["run_id"], "Portal")
        capability, _ = self.plane.issue_capability(
            run_id=run["run_id"],
            scopes=["issues.create"],
            resources=["github://repos/acme/*"],
            ttl_seconds=300,
        )
        key = self.plane.api_keys.mint(
            key_type="runtime",
            name="portal-runtime",
            scopes=["actions:execute"],
            agent_id="github-agent",
            expires_in=600,
            cidr_allowlist=[],
            parent_key_id=None,
            actor="admin",
        )
        payload = {
            "capability_token": capability,
            "runtime_proof": run["runtime_proof"],
            "request_nonce": str(uuid4()),
            "task_id": task["task_id"],
            "connector_id": "portal-github",
            "action": "issues.create",
            "resource": "github://repos/acme/app/issues",
            "parameters": {"title": "Synthetic issue"},
            "data_classification": "internal",
            "environment": "test",
            "grant_id": grant_id,
        }
        paused = self.client.post(
            "/actions/execute", headers={"X-Warden-Key": key["api_key"]}, json=payload
        ).json()
        self.assertEqual("approval_required", paused["status"])
        self.plane.resolve_approval(
            paused["approval_id"], True, "user-1", "Portal approval"
        )
        payload.update(request_nonce=str(uuid4()), approval_id=paused["approval_id"])
        completed = self.client.post(
            "/actions/execute", headers={"X-Warden-Key": key["api_key"]}, json=payload
        ).json()
        self.assertEqual("executed", completed["status"])
        trace = self.plane.enforcement_trace(completed["tool_call_id"])
        self.assertNotIn("unrecorded", {item["status"] for item in trace["stages"]})
        self.plane.api_keys.revoke(key["key_id"], "admin")
        payload["request_nonce"] = str(uuid4())
        revoked = self.client.post(
            "/actions/execute", headers={"X-Warden-Key": key["api_key"]}, json=payload
        )
        self.assertEqual("revoked", revoked.json()["error"]["code"])


if __name__ == "__main__":
    unittest.main()
