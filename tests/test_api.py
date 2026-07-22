from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from control_plane.config import Settings
from control_plane.service import ControlPlane
import control_plane.api as api_module


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        api_module.plane = ControlPlane(
            Settings(
                database_path=root / "api.db",
                data_dir=root,
                issuer="api-test",
                audience="api-gateway",
                admin_key="admin-key",
                environment="test",
                allowed_egress_hosts=(),
            )
        )
        self.client = TestClient(api_module.app)
        self.admin = {"X-Admin-Key": "admin-key"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_health_and_admin_authentication(self) -> None:
        with patch.object(
            api_module.plane.audit,
            "verify",
            side_effect=AssertionError("probes must not scan the audit ledger"),
        ):
            self.assertEqual(
                {"status": "ok", "service": "warden-agent-control-plane"},
                self.client.get("/health").json(),
            )
            self.assertEqual({"status": "ready"}, self.client.get("/ready").json())
        self.assertEqual({"status": "ok"}, self.client.get("/live").json())
        self.assertEqual(200, self.client.get("/documentation").status_code)
        self.assertEqual(200, self.client.get("/index.html").status_code)
        self.assertIn("Warden Control Plane", self.client.get("/console").text)
        self.assertEqual(200, self.client.get("/openapi.html").status_code)
        for path in (
            "/onboarding",
            "/onboarding.js",
            "/policies",
            "/policies.js",
            "/connections",
            "/connections.js",
            "/warden-connect.js",
            "/oauth-result.js",
            "/portal",
            "/portal.js",
            "/portal.css",
            "/sdk/warden.js",
            "/product.css",
        ):
            self.assertEqual(200, self.client.get(path).status_code, path)
        self.assertEqual(401, self.client.get("/admin/agents").status_code)
        self.assertEqual(
            200, self.client.get("/admin/agents", headers=self.admin).status_code
        )

    def test_visual_policy_builder_uses_versioned_policy_api(self) -> None:
        created = self.client.post(
            "/admin/policies",
            headers=self.admin,
            json={
                "policy_id": "visual-policy",
                "layer": "agent",
                "target_id": "agent-a",
                "rules": {"deny_actions": ["users.delete"]},
            },
        )
        self.assertEqual(200, created.status_code)
        policies = self.client.get("/admin/policies", headers=self.admin)
        self.assertEqual(200, policies.status_code)
        self.assertTrue(
            any(
                item["rules"].get("deny_actions") == ["users.delete"]
                for item in policies.json()
            )
        )

    def test_guided_onboarding_reaches_first_protected_call(self) -> None:
        agent_id = "onboarding-agent"
        action = "blog.publish_post"
        resource = "cms://vouchins/blog/first-post"
        self.client.post(
            "/admin/owners",
            headers=self.admin,
            json={"owner_id": "onboarding-team", "name": "Onboarding Team"},
        )
        registered = self.client.post(
            "/admin/agents",
            headers=self.admin,
            json={
                "agent_id": agent_id,
                "name": "Onboarding Agent",
                "owner": "onboarding-team",
                "purpose": "Publish one bounded post",
                "model_provider": "owner-supplied",
                "agent_version": "1.0.0",
                "environment": "test",
                "risk_tier": "medium",
                "allowed_tools": ["cms"],
                "allowed_actions": [action],
                "allowed_data_classifications": ["public"],
                "max_delegation_depth": 0,
                "approved_parents": [],
                "approved_children": [],
            },
        )
        self.assertEqual(200, registered.status_code)
        self.client.post(
            f"/admin/agents/{agent_id}/approve", headers=self.admin, json={}
        )
        connector = self.client.post(
            "/admin/connectors",
            headers=self.admin,
            json={
                "connector_id": "onboarding-cms",
                "tool": "cms",
                "action": action,
                "adapter_type": "local_emulator",
                "http_method": "POST",
                "resource_patterns": ["cms://vouchins/blog/*"],
                "required_scopes": [action],
                "owner": "onboarding-team",
                "risk_tier": "low",
                "rate_limit_per_minute": 10,
                "credential_mode": "bearer",
                "credential_config": {},
                "grant_required": True,
            },
        )
        self.assertEqual(200, connector.status_code)
        policy = self.client.post(
            "/admin/policies",
            headers=self.admin,
            json={
                "policy_id": "onboarding-agent-starter-policy",
                "layer": "agent",
                "target_id": agent_id,
                "rules": {
                    "approval_for_production_writes": True,
                    "require_grants_for_external": True,
                },
            },
        )
        self.assertEqual(200, policy.status_code)
        connection = self.client.post(
            "/admin/connections/managed",
            headers=self.admin,
            json={
                "provider_id": "vouchins-admin-api",
                "owner_principal_id": "onboarding-user",
                "account_identifier": "onboarding-account",
                "credential": {"value": "not-a-production-secret"},
                "principal_type": "agent",
                "principal_id": agent_id,
                "label": "first-call",
                "grant_scopes": [action],
                "allowed_methods": ["POST"],
                "path_patterns": ["/*"],
                "ttl_seconds": 3600,
                "reason": "Guided onboarding test",
            },
        ).json()
        run = self.client.post(
            "/runs",
            json={
                "principal_id": "onboarding-user",
                "agent_id": agent_id,
                "task": "Execute the onboarding test call",
                "environment": "test",
            },
        ).json()
        task = self.client.post(
            "/tasks",
            json={
                "run_id": run["run_id"],
                "description": "First protected call",
            },
        ).json()
        capability = self.client.post(
            "/admin/capabilities/issue",
            headers=self.admin,
            json={
                "run_id": run["run_id"],
                "scopes": [action],
                "resources": [resource],
                "ttl_seconds": 300,
            },
        ).json()
        executed = self.client.post(
            "/actions/execute",
            json={
                "capability_token": capability["capability_token"],
                "runtime_proof": run["runtime_proof"],
                "request_nonce": str(uuid4()),
                "task_id": task["task_id"],
                "connector_id": "onboarding-cms",
                "action": action,
                "resource": resource,
                "parameters": {"title": "First post"},
                "data_classification": "public",
                "environment": "test",
                "grant_id": connection["grant"]["grant_id"],
                "risk_signals": {"onboarding": True},
            },
        )
        self.assertEqual(200, executed.status_code, executed.text)
        self.assertEqual("executed", executed.json()["status"], executed.text)

    def test_owner_can_submit_but_not_self_approve(self) -> None:
        created = self.client.post(
            "/admin/owners",
            headers=self.admin,
            json={"owner_id": "team-a", "name": "Team A", "roles": ["agent-owner"]},
        ).json()
        owner_headers = {"X-Owner-Id": "team-a", "X-Owner-Key": created["api_key"]}
        manifest = {
            "agent_id": "agent-a",
            "name": "Agent A",
            "owner": "team-a",
            "purpose": "Read bounded records",
            "model_provider": "any",
            "agent_version": "1",
            "environment": "dev",
            "risk_tier": "low",
            "allowed_tools": ["records"],
            "allowed_actions": ["records.read"],
            "allowed_data_classifications": ["internal"],
            "max_delegation_depth": 0,
            "approved_parents": [],
            "approved_children": [],
        }
        response = self.client.post(
            "/owners/agents", headers=owner_headers, json=manifest
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("pending", response.json()["status"])
        self.assertEqual(
            401,
            self.client.post(
                "/admin/agents/agent-a/approve", headers=owner_headers
            ).status_code,
        )

    def test_rest_mcp_and_a2a_facades_share_gateway(self) -> None:
        plane = api_module.plane
        plane.seed_policy({}, "admin")
        plane.register_agent(
            {
                "agent_id": "generic-agent",
                "name": "Generic Agent",
                "owner": "team",
                "purpose": "Exercise every ingress",
                "model_provider": "any",
                "agent_version": "1",
                "environment": "test",
                "risk_tier": "low",
                "allowed_tools": ["records"],
                "allowed_actions": ["records.update", "records.read"],
                "allowed_data_classifications": ["internal"],
                "max_delegation_depth": 0,
                "approved_parents": [],
                "approved_children": [],
            },
            "team",
        )
        plane.approve_agent("generic-agent", "admin")
        for action in ("records.update", "records.read"):
            plane.register_connector(
                {
                    "connector_id": action.replace(".", "-"),
                    "tool": "records",
                    "action": action,
                    "adapter_type": "local_emulator",
                    "resource_patterns": ["records://*"],
                    "required_scopes": [action],
                    "owner": "team",
                    "risk_tier": "low",
                },
                "team",
            )
        run = plane.create_run("api-user", "generic-agent", "Exercise ingress", "test")
        task = plane.create_task(run["run_id"], "Update and read record")
        token, _ = plane.issue_capability(
            run_id=run["run_id"],
            scopes=["records.update", "records.read"],
            resources=["records://*"],
            ttl_seconds=300,
        )
        base = {
            "capability_token": token,
            "runtime_proof": run["runtime_proof"],
            "task_id": task["task_id"],
            "resource": "records://one",
            "parameters": {"value": {"ok": True}},
            "data_classification": "internal",
            "environment": "test",
            "risk_signals": {},
            "approval_id": None,
        }
        rest = self.client.post(
            "/actions/execute",
            json={
                **base,
                "request_nonce": str(uuid4()),
                "connector_id": "records-update",
                "action": "records.update",
            },
        )
        mcp = self.client.post(
            "/mcp/tools/call",
            json={
                "method": "tools/call",
                "params": {
                    **base,
                    "request_nonce": str(uuid4()),
                    "connector_id": "records-read",
                    "action": "records.read",
                },
            },
        )
        a2a = self.client.post(
            "/a2a/message:send",
            json={
                "message_type": "message:send",
                "action_request": {
                    **base,
                    "request_nonce": str(uuid4()),
                    "connector_id": "records-read",
                    "action": "records.read",
                },
            },
        )
        self.assertEqual("executed", rest.json()["status"])
        self.assertEqual("executed", mcp.json()["result"]["status"])
        self.assertEqual("executed", a2a.json()["result"]["status"])
        self.assertTrue(self.client.get("/audit/verify").json()["valid"])
        self.assertEqual(
            "application/x-ndjson",
            self.client.get("/audit/export.ndjson").headers["content-type"],
        )

    def test_connection_grant_and_layered_policy_management_apis(self) -> None:
        secret = self.client.post(
            "/admin/secrets",
            headers=self.admin,
            json={
                "alias": "github-client",
                "value": "not-returned",
                "provider": "oauth",
            },
        )
        self.assertEqual(200, secret.status_code)
        provider = self.client.post(
            "/admin/oauth/providers/github",
            headers=self.admin,
            json={
                "provider_id": "github",
                "client_id": "github-client-id",
                "client_secret_alias": "github-client",
                "default_scopes": ["repo"],
            },
        )
        self.assertEqual(200, provider.status_code)
        connect_input = {
            "principal_id": "api-user",
            "agent_id": None,
            "label": "github",
            "provider_scopes": ["repo"],
            "grant_scopes": ["issues.create"],
            "allowed_methods": ["POST"],
            "path_patterns": ["/repos/acme/*"],
            "reason": "Bounded issue access",
            "allowed_providers": ["github"],
            "ttl_seconds": 600,
        }
        session = self.client.post(
            "/admin/connect/sessions", headers=self.admin, json=connect_input
        )
        self.assertEqual(200, session.status_code)
        started = self.client.post(
            "/connect/github/start",
            json={
                "session_token": session.json()["session_token"],
            },
        )
        self.assertEqual(200, started.status_code)
        self.assertIn(
            "https://github.com/login/oauth/authorize", started.json()["connect_url"]
        )

        managed = self.client.post(
            "/admin/connections/managed",
            headers=self.admin,
            json={
                "provider_id": "example",
                "owner_principal_id": "api-user",
                "account_identifier": "account-1",
                "credential": {"value": "api-secret"},
                "principal_type": "user",
                "principal_id": "api-user",
                "label": "default",
                "grant_scopes": ["records.read"],
                "allowed_methods": ["GET"],
                "path_patterns": ["/records/*"],
                "ttl_seconds": 300,
                "reason": "Read records",
            },
        )
        self.assertEqual(200, managed.status_code)
        body = managed.json()
        self.assertNotIn("api-secret", managed.text)
        connection_id = body["connection"]["connection_id"]
        grant_id = body["grant"]["grant_id"]
        self.assertEqual(
            1,
            len(
                self.client.get(
                    "/me/connections", params={"principal_id": "api-user"}
                ).json()
            ),
        )
        self.assertEqual(
            1,
            len(
                self.client.get(
                    "/me/grants", params={"principal_id": "api-user"}
                ).json()
            ),
        )

        policy = self.client.post(
            "/admin/policies",
            headers=self.admin,
            json={
                "policy_id": "records-guard",
                "layer": "connector",
                "target_id": "records-read",
                "rules": {"deny_actions": ["records.delete"]},
            },
        )
        self.assertEqual("connector", policy.json()["layer"])
        revoked = self.client.post(
            f"/me/grants/{grant_id}/revoke",
            params={"principal_id": "api-user"},
            json={"reason": "No longer needed"},
        )
        self.assertEqual("revoked", revoked.json()["status"])
        self.client.post(
            f"/me/connections/{connection_id}/revoke",
            params={"principal_id": "api-user"},
            json={"reason": "Disconnect"},
        )


if __name__ == "__main__":
    unittest.main()
