from __future__ import annotations

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from uuid import uuid4

from control_plane.config import Settings
from control_plane.crypto import CapabilityError
from control_plane.service import ControlPlane, ControlPlaneError


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.plane = ControlPlane(Settings(
            database_path=root / "warden.db", data_dir=root,
            issuer="test-issuer", audience="test-gateway", admin_key="admin-test-key",
            environment="test", allowed_egress_hosts=(),
        ))
        self.plane.seed_policy({}, "test-admin")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _manifest(self, agent_id: str = "inventory-agent") -> dict:
        return {
            "agent_id": agent_id, "name": "Inventory Agent", "owner": "inventory-team",
            "purpose": "Maintain bounded inventory resources", "model_provider": "any-runtime",
            "agent_version": "1.0.0", "environment": "test", "risk_tier": "medium",
            "allowed_tools": ["inventory"],
            "allowed_actions": ["inventory.read", "inventory.update"],
            "allowed_data_classifications": ["internal"], "max_delegation_depth": 0,
            "approved_parents": [], "approved_children": [],
        }

    def _generic_runtime(self, rate_limit: int = 30):
        self.plane.register_agent(self._manifest(), "inventory-team")
        self.plane.approve_agent("inventory-agent", "test-admin")
        for action in ("inventory.update", "inventory.read"):
            self.plane.register_connector({
                "connector_id": action.replace(".", "-"), "tool": "inventory", "action": action,
                "adapter_type": "local_emulator", "resource_patterns": ["inventory://item/*"],
                "required_scopes": [action], "owner": "inventory-team", "risk_tier": "low",
                "rate_limit_per_minute": rate_limit,
            }, "inventory-team")
        run = self.plane.create_run("human-123", "inventory-agent", "Update one item", "test")
        task = self.plane.create_task(run["run_id"], "Update SKU-1")
        token, claims = self.plane.issue_capability(
            run_id=run["run_id"], scopes=["inventory.update", "inventory.read"],
            resources=["inventory://item/*"], ttl_seconds=300,
        )
        return run, task, token, claims

    def _execute(self, token: str, task_id: str, action: str, nonce: str | None = None):
        return self.plane.execute_action(
            token=token, runtime_proof=self.current_run["runtime_proof"],
            request_nonce=nonce or str(uuid4()), task_id=task_id,
            connector_id=action.replace(".", "-"), action=action,
            resource="inventory://item/SKU-1", parameters={"value": {"quantity": 9}},
            data_classification="internal", environment="test",
        )

    def test_plug_and_play_agent_and_generic_connector(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        updated = self._execute(token, task["task_id"], "inventory.update")
        read = self._execute(token, task["task_id"], "inventory.read")
        self.assertEqual("executed", updated["status"])
        self.assertEqual(9, read["result"]["value"]["quantity"])

    def test_stale_execution_claims_are_marked_uncertain(self) -> None:
        self.plane.database.execute(
            "INSERT INTO execution_requests VALUES(?,?,?,?,?,?,?)",
            ("stale-jti", "stale-key", "hash", "processing", None,
             "2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00"),
        )
        result = self.plane.reconcile_stale_operations("test-admin", 60)
        row = self.plane.database.one(
            "SELECT status,response_json FROM execution_requests WHERE token_jti=?",
            ("stale-jti",),
        )
        self.assertEqual(1, result["executions_marked_uncertain"])
        self.assertEqual("uncertain", row["status"])
        self.assertNotIn("secret", row["response_json"])

    def test_owner_credentials_and_pending_manifests(self) -> None:
        owner = self.plane.create_owner("inventory-team", "Inventory Team", ["agent-owner"], "admin")
        self.assertEqual("inventory-team", self.plane.authenticate_owner("inventory-team", owner["api_key"]))
        with self.assertRaises(ControlPlaneError):
            self.plane.authenticate_owner("inventory-team", "wrong")

    def test_agent_version_update_requires_reapproval(self) -> None:
        manifest = self._manifest()
        self.plane.register_agent(manifest, "inventory-team")
        self.plane.approve_agent("inventory-agent", "admin")
        updated = {**manifest, "agent_version": "2.0.0", "purpose": "Updated bounded purpose"}
        result = self.plane.update_agent("inventory-agent", updated, "inventory-team")
        self.assertEqual("pending", result["status"])
        versions = self.plane.database.all("SELECT status FROM agent_versions WHERE agent_id=? ORDER BY agent_version", ("inventory-agent",))
        self.assertEqual(["approved", "pending"], [row["status"] for row in versions])

    def test_capability_is_rs256_audience_bound_and_tamper_evident(self) -> None:
        self.current_run, _, token, claims = self._generic_runtime()
        self.assertEqual("test-issuer", claims["iss"])
        self.assertEqual("test-gateway", claims["aud"])
        self.assertEqual(claims["jti"], self.plane.capabilities.verify(token)["jti"])
        tampered = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
        with self.assertRaises(CapabilityError):
            self.plane.capabilities.verify(tampered)

    def test_expired_and_revoked_tokens_fail_immediately(self) -> None:
        self.current_run, _, token, claims = self._generic_runtime()
        with patch("control_plane.crypto.time.time", return_value=claims["exp"] + 1):
            with self.assertRaisesRegex(CapabilityError, "expired"):
                self.plane.capabilities.verify(token)
        self.plane.revoke_token(claims["jti"], "admin", "incident")
        with self.assertRaisesRegex(CapabilityError, "revoked"):
            self.plane.capabilities.verify(token)

    def test_key_rotation_keeps_old_verification_until_key_revocation(self) -> None:
        self.current_run, _, token, claims = self._generic_runtime()
        self.plane.capabilities.rotate_key("admin")
        self.assertEqual(claims["jti"], self.plane.capabilities.verify(token)["jti"])
        old_kid = self.plane.database.one("SELECT kid FROM tokens WHERE jti=?", (claims["jti"],))["kid"]
        self.plane.capabilities.revoke_key(old_kid, "admin", "key compromised")
        with self.assertRaisesRegex(CapabilityError, "revoked"):
            self.plane.capabilities.verify(token)

    def test_idempotent_replay_returns_original_response(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        nonce = str(uuid4())
        self.assertEqual("executed", self._execute(token, task["task_id"], "inventory.update", nonce)["status"])
        replay = self._execute(token, task["task_id"], "inventory.update", nonce)
        self.assertEqual("executed", replay["status"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(1, len(self.plane.database.all("SELECT * FROM execution_requests")))

    def test_idempotency_key_cannot_be_reused_for_different_request(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        nonce = str(uuid4())
        self._execute(token, task["task_id"], "inventory.update", nonce)
        result = self.plane.execute_action(
            token=token, runtime_proof=self.current_run["runtime_proof"],
            request_nonce=nonce, task_id=task["task_id"],
            connector_id="inventory-update", action="inventory.update",
            resource="inventory://item/SKU-1", parameters={"value": {"quantity": 99}},
            data_classification="internal", environment="test",
        )
        self.assertEqual("denied", result["status"])
        self.assertIn("different request", result["reason"])

    def test_delegation_requires_parent_proof_of_possession(self) -> None:
        self.plane.bootstrap_support_demo("admin")
        parent = self.plane.create_run("human", "support-triage", "Support", "prod")
        token, _ = self.plane.issue_capability(
            run_id=parent["run_id"], scopes=["github.read"],
            resources=["github://repo/acme/*"], ttl_seconds=300,
        )
        child = self.plane.create_run("human", "code-reviewer", "Review", "prod", parent["run_id"])
        with self.assertRaisesRegex(ControlPlaneError, "Runtime proof mismatch"):
            self.plane.delegate_capability(
                parent_token=token, parent_runtime_proof="stolen-token-without-valid-proof",
                child_run_id=child["run_id"], scopes=["github.read"],
                resources=["github://repo/acme/support"], ttl_seconds=60,
            )

    def test_approval_is_atomically_single_use(self) -> None:
        self.plane.bootstrap_support_demo("admin")
        run = self.plane.create_run("human", "support-triage", "Update", "prod")
        task = self.plane.create_task(run["run_id"], "Update case")
        token, _ = self.plane.capabilities.issue(
            agent_id="support-triage", run_id=run["run_id"], principal_id="human",
            scopes=["crm.update_case", "data:sensitive"],
            resources=["crm://case/CASE-1042"], ttl_seconds=300,
        )
        request = dict(
            token=token, runtime_proof=run["runtime_proof"], task_id=task["task_id"],
            connector_id="crm-case-update", action="crm.update_case",
            resource="crm://case/CASE-1042", parameters={"update": "Started"},
            data_classification="sensitive", environment="prod",
        )
        pending = self.plane.execute_action(**request, request_nonce=str(uuid4()))
        self.plane.resolve_approval(pending["approval_id"], True, "admin")
        first = self.plane.execute_action(
            **request, approval_id=pending["approval_id"], request_nonce=str(uuid4())
        )
        second = self.plane.execute_action(
            **request, approval_id=pending["approval_id"], request_nonce=str(uuid4())
        )
        self.assertEqual("executed", first["status"])
        self.assertEqual("approval_required", second["status"])
        self.assertEqual(
            "consumed",
            self.plane.database.one(
                "SELECT status FROM approvals WHERE approval_id=?", (pending["approval_id"],)
            )["status"],
        )

    def test_resource_canonicalization_rejects_encoded_traversal(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        result = self.plane.execute_action(
            token=token, runtime_proof=self.current_run["runtime_proof"],
            request_nonce=str(uuid4()), task_id=task["task_id"],
            connector_id="inventory-read", action="inventory.read",
            resource="inventory://item/%2e%2e/admin", parameters={},
            data_classification="internal", environment="test",
        )
        self.assertEqual("denied", result["status"])
        self.assertIn("Percent-encoded", result["reason"])

    def test_runtime_proof_prevents_token_transfer(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        result = self.plane.execute_action(
            token=token, runtime_proof="wrong-runtime-proof-value",
            request_nonce=str(uuid4()), task_id=task["task_id"],
            connector_id="inventory-update", action="inventory.update",
            resource="inventory://item/SKU-1", parameters={"value": {"quantity": 1}},
            data_classification="internal", environment="test",
        )
        self.assertEqual("denied", result["status"])
        self.assertIn("Runtime proof mismatch", result["reason"])

    def test_scope_resource_tool_and_data_policy_fail_closed(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        result = self.plane.execute_action(
            token=token, request_nonce=str(uuid4()), task_id=task["task_id"],
            runtime_proof=self.current_run["runtime_proof"],
            connector_id="inventory-update", action="inventory.update",
            resource="inventory://other/SKU-1", parameters={},
            data_classification="restricted", environment="test",
        )
        self.assertEqual("denied", result["status"])

    def test_rate_limit_and_kill_switch(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime(rate_limit=1)
        self.assertEqual("executed", self._execute(token, task["task_id"], "inventory.update")["status"])
        self.assertIn("rate limit", self._execute(token, task["task_id"], "inventory.update")["reason"])
        self.plane.set_kill_switch(True, "admin")
        self.assertIn("kill switch", self._execute(token, task["task_id"], "inventory.read")["reason"])

    def test_policy_revocation_fails_closed(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        self.plane.revoke_policy("default", "admin", "bad policy")
        result = self._execute(token, task["task_id"], "inventory.update")
        self.assertEqual("denied", result["status"])
        self.assertIn("No active policy", result["reason"])

    def test_run_and_agent_revocation_invalidate_authority(self) -> None:
        self.current_run, task, token, _ = self._generic_runtime()
        run = self.current_run
        self.plane.revoke_run(run["run_id"], "admin", "user cancelled")
        self.assertEqual("denied", self._execute(token, task["task_id"], "inventory.update")["status"])

    def test_overbroad_delegation_is_rejected(self) -> None:
        self.plane.bootstrap_support_demo("admin")
        parent = self.plane.create_run("human", "support-triage", "Support", "prod")
        token, _ = self.plane.issue_capability(
            run_id=parent["run_id"], scopes=["github.read"],
            resources=["github://repo/acme/*"], ttl_seconds=300,
        )
        child = self.plane.create_run("human", "code-reviewer", "Review", "prod", parent["run_id"])
        with self.assertRaisesRegex(ControlPlaneError, "scopes"):
            self.plane.delegate_capability(
                parent_token=token, parent_runtime_proof=parent["runtime_proof"],
                child_run_id=child["run_id"], scopes=["github.write"],
                resources=["github://repo/acme/support"], ttl_seconds=60,
            )

    def test_parent_token_revocation_invalidates_child_authority(self) -> None:
        self.plane.bootstrap_support_demo("admin")
        parent_run = self.plane.create_run("human", "support-triage", "Support", "prod")
        parent_token, parent_claims = self.plane.issue_capability(
            run_id=parent_run["run_id"], scopes=["github.read"],
            resources=["github://repo/acme/*"], ttl_seconds=300,
        )
        child_run = self.plane.create_run("human", "code-reviewer", "Review", "prod", parent_run["run_id"])
        child_token, _ = self.plane.delegate_capability(
            parent_token=parent_token, parent_runtime_proof=parent_run["runtime_proof"],
            child_run_id=child_run["run_id"], scopes=["github.read"],
            resources=["github://repo/acme/support"], ttl_seconds=60,
        )
        self.plane.revoke_token(parent_claims["jti"], "admin", "parent compromised")
        with self.assertRaisesRegex(CapabilityError, "Parent capability"):
            self.plane.capabilities.verify(child_token)

    def test_secret_values_are_redacted_from_audit(self) -> None:
        self.plane.secrets.store("api-alias", "super-secret-value", "admin")
        exported = "".join(self.plane.audit.export_ndjson())
        self.assertNotIn("super-secret-value", exported)

    def test_audit_hash_chain_detects_tampering(self) -> None:
        self.plane.audit.append("test.event", "tester", payload={"safe": "value"})
        self.assertTrue(self.plane.audit.verify()["valid"])
        self.plane.database.execute("UPDATE audit_events SET payload='{}' WHERE sequence=(SELECT MAX(sequence) FROM audit_events)")
        self.assertFalse(self.plane.audit.verify()["valid"])

    def test_support_ticket_reference_scenario(self) -> None:
        result = self.plane.run_support_ticket_scenario("support-user", "admin")
        self.assertEqual("completed", result["status"])
        self.assertTrue(result["audit"]["valid"])
        statuses = {item["step"]: item["status"] for item in result["outcomes"]}
        self.assertEqual("approval_required", statuses["crm_update_requires_approval"])
        self.assertEqual("executed", statuses["crm_updated"])
        self.assertEqual("executed", statuses["email_drafted"])
        self.assertEqual("executed", statuses["jira_created"])
        self.assertEqual("executed", statuses["child_code_review"])


if __name__ == "__main__":
    unittest.main()
