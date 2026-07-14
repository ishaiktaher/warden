from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import requests

from control_plane.config import Settings
from control_plane.connectors import (
    ConnectorDispatcher, ConnectorError, MAX_CONNECTOR_RESPONSE_BYTES,
)
from control_plane.credentials import CredentialError
from control_plane.service import ControlPlane


class CredentialGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.plane = ControlPlane(Settings(
            database_path=root / "warden.db", data_dir=root,
            issuer="test-issuer", audience="test-gateway",
            admin_key="test-admin", environment="test",
            allowed_egress_hosts=("api.example.com",),
        ))
        self.plane.seed_policy({}, "admin")
        self.plane.register_agent({
            "agent_id": "github-agent", "name": "GitHub Agent",
            "owner": "engineering", "purpose": "Manage bounded issues",
            "model_provider": "any", "agent_version": "1.0.0",
            "environment": "test", "risk_tier": "medium",
            "allowed_tools": ["github"], "allowed_actions": ["issues.create"],
            "allowed_data_classifications": ["internal"],
            "max_delegation_depth": 0, "approved_parents": [],
            "approved_children": [],
        }, "engineering")
        self.plane.approve_agent("github-agent", "admin")
        self.plane.register_connector({
            "connector_id": "github-issues", "tool": "github",
            "action": "issues.create", "adapter_type": "rest",
            "endpoint": "https://api.example.com/repos/acme/app/issues",
            "http_method": "POST", "resource_patterns": ["repo://acme/app"],
            "required_scopes": ["issues.create"], "owner": "engineering",
            "risk_tier": "low", "credential_mode": "custom_header",
            "credential_config": {"header_name": "X-API-Key"},
            "grant_required": True,
        }, "engineering")
        self.run = self.plane.create_run(
            "user-123", "github-agent", "Create an issue", "test"
        )
        self.task = self.plane.create_task(self.run["run_id"], "Create issue")
        self.token, _ = self.plane.issue_capability(
            run_id=self.run["run_id"], scopes=["issues.create"],
            resources=["repo://acme/app"], ttl_seconds=300,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _connection(self, *, methods: list[str] | None = None,
                    paths: list[str] | None = None) -> dict:
        created = self.plane.credentials.create_managed_connection(
            provider_id="generic-api", owner_principal_id="user-123",
            account_identifier="acme", credential={"value": "top-secret-api-key"},
            principal_type="user", principal_id="user-123", label=str(uuid4()),
            grant_scopes=["issues.create"], allowed_methods=methods or ["POST"],
            path_patterns=paths or ["/repos/acme/app/issues"], ttl_seconds=300,
            reason="Create bounded issues", actor="control-plane-admin",
        )
        self.plane.credentials.delegate_grant(
            created["grant"]["grant_id"], "github-agent", "user-123",
            "Agent owns the issue task",
        )
        return created

    def _execute(self, grant_id: str) -> dict:
        return self.plane.execute_action(
            token=self.token, runtime_proof=self.run["runtime_proof"],
            request_nonce=str(uuid4()), task_id=self.task["task_id"],
            connector_id="github-issues", action="issues.create",
            resource="repo://acme/app", parameters={"title": "Bug"},
            data_classification="internal", environment="test",
            grant_id=grant_id,
        )

    @patch("control_plane.connectors.ConnectorDispatcher._validate_public_host")
    @patch("control_plane.connectors.ConnectorDispatcher._pinned_json_request")
    def test_grant_injects_secret_only_at_gateway_and_revocation_is_immediate(
        self, request: Mock, _validate: Mock,
    ) -> None:
        created = self._connection()
        grant_id = created["grant"]["grant_id"]
        _validate.return_value = ("93.184.216.34",)
        request.return_value = {"id": 123, "status": "created"}

        result = self._execute(grant_id)
        self.assertEqual("executed", result["status"])
        self.assertEqual("top-secret-api-key", request.call_args.kwargs["headers"]["X-API-Key"])
        self.assertNotIn("top-secret-api-key", json.dumps(result))
        self.assertNotIn(
            "top-secret-api-key", json.dumps(self.plane.audit.events(limit=500))
        )

        self.plane.credentials.revoke_grant(grant_id, "user-123", "Task complete")
        blocked = self._execute(grant_id)
        self.assertEqual("denied", blocked["status"])
        self.assertIn("unavailable", blocked["reason"])
        self.assertEqual(1, request.call_count)

    @patch("control_plane.connectors.ConnectorDispatcher._validate_public_host")
    @patch("control_plane.connectors.ConnectorDispatcher._pinned_json_request")
    def test_method_path_and_agent_restrictions_fail_before_network(
        self, request: Mock, _validate: Mock,
    ) -> None:
        wrong_method = self._connection(methods=["GET"])
        result = self._execute(wrong_method["grant"]["grant_id"])
        self.assertIn("method", result["reason"].lower())

        wrong_path = self._connection(paths=["/repos/acme/other/*"])
        result = self._execute(wrong_path["grant"]["grant_id"])
        self.assertIn("path", result["reason"].lower())

        undelegated = self.plane.credentials.create_managed_connection(
            provider_id="generic-api", owner_principal_id="user-123",
            account_identifier="acme", credential={"value": "different-secret"},
            principal_type="user", principal_id="user-123", label=str(uuid4()),
            grant_scopes=["issues.create"], allowed_methods=["POST"],
            path_patterns=["/repos/acme/app/issues"], ttl_seconds=300,
            reason="Not delegated", actor="control-plane-admin",
        )
        result = self._execute(undelegated["grant"]["grant_id"])
        self.assertIn("not delegated", result["reason"].lower())
        request.assert_not_called()

    @patch("control_plane.credentials.requests.get")
    @patch("control_plane.credentials.requests.post")
    def test_github_oauth_state_is_single_use_and_creates_delegated_grant(
        self, post: Mock, get: Mock,
    ) -> None:
        self.plane.secrets.store("github-client-secret", "client-secret", "admin")
        self.plane.credentials.register_github_provider(
            client_id="github-client-id", client_secret_alias="github-client-secret",
            default_scopes=["repo"], owner="admin",
        )
        started = self.plane.credentials.start_github_connect(
            principal_id="user-123", agent_id="github-agent", label="work",
            provider_scopes=["repo"], grant_scopes=["issues.create"],
            allowed_methods=["POST"], path_patterns=["/repos/acme/app/issues"],
            ttl_seconds=300, reason="Authorize issue creation",
        )
        state = parse_qs(urlparse(started["connect_url"]).query)["state"][0]
        token_response = Mock()
        token_response.json.return_value = {
            "access_token": "github-access-token", "token_type": "bearer",
            "scope": "repo",
        }
        token_response.raise_for_status.return_value = None
        post.return_value = token_response
        identity_response = Mock()
        identity_response.json.return_value = {"id": 42, "login": "octocat"}
        identity_response.raise_for_status.return_value = None
        get.return_value = identity_response

        completed = self.plane.credentials.complete_github_connect(
            code="oauth-code", state=state
        )
        self.assertEqual("connected", completed["status"])
        grant_id = completed["grant"]["grant_id"]
        delegation = self.plane.database.one(
            "SELECT status FROM grant_delegations WHERE grant_id=? AND agent_id=?",
            (grant_id, "github-agent"),
        )
        self.assertEqual("active", delegation["status"])
        with self.assertRaises(CredentialError):
            self.plane.credentials.complete_github_connect(code="again", state=state)
        self.assertEqual(1, post.call_count)

    def test_connector_layer_can_only_narrow_platform_policy(self) -> None:
        self.plane.seed_policy(
            {"deny_actions": ["issues.create"]}, "admin", "deny-github-writes",
            layer="connector", target_id="github-issues",
        )
        created = self._connection()
        with patch("control_plane.connectors.ConnectorDispatcher._pinned_json_request") as request:
            result = self._execute(created["grant"]["grant_id"])
        self.assertEqual("denied", result["status"])
        self.assertIn("layered policy", result["reason"].lower())
        request.assert_not_called()
        denied = self.plane.audit.events(event_type="policy.denied", limit=10)[0]
        self.assertTrue(denied["payload"]["policy_layers"])

    @patch("control_plane.connectors.requests.Session")
    def test_connector_transport_pins_ip_preserves_tls_host_and_streams(self, session_type: Mock) -> None:
        session = session_type.return_value
        response = Mock()
        response.status_code = 200
        response.headers = {
            "Content-Type": "application/json", "Content-Length": "13",
        }
        response.iter_content.return_value = [b'{"ok":', b'true}']
        response.raise_for_status.return_value = None
        session.request.return_value = response

        result = ConnectorDispatcher._pinned_json_request(
            "POST", "https://api.example.com/v1/actions", "api.example.com",
            ("93.184.216.34",), headers={"Content-Type": "application/json"},
            json_body={"action": "test"},
        )

        self.assertEqual({"ok": True}, result)
        self.assertFalse(session.trust_env)
        self.assertEqual(
            "https://93.184.216.34/v1/actions", session.request.call_args.args[1]
        )
        sent_headers = session.request.call_args.kwargs["headers"]
        self.assertEqual("api.example.com", sent_headers["Host"])
        self.assertEqual("identity", sent_headers["Accept-Encoding"])
        self.assertTrue(session.request.call_args.kwargs["stream"])
        response.close.assert_called_once()
        session.close.assert_called_once()

    @patch("control_plane.connectors.requests.Session")
    def test_connector_transport_stops_after_response_limit(self, session_type: Mock) -> None:
        session = session_type.return_value
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/json"}
        response.iter_content.return_value = [
            b"x" * MAX_CONNECTOR_RESPONSE_BYTES, b"x",
        ]
        response.raise_for_status.return_value = None
        session.request.return_value = response

        with self.assertRaisesRegex(ConnectorError, "exceeds the 1 MiB limit"):
            ConnectorDispatcher._pinned_json_request(
                "GET", "https://api.example.com/data", "api.example.com",
                ("93.184.216.34",), headers={},
            )
        response.close.assert_called_once()
        session.close.assert_called_once()

    @patch("control_plane.connectors.socket.getaddrinfo")
    def test_connector_resolution_rejects_any_non_public_answer(self, resolve: Mock) -> None:
        resolve.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.2", 443)),
        ]
        with self.assertRaisesRegex(ConnectorError, "non-public"):
            ConnectorDispatcher._validate_public_host("api.example.com")

    def test_delegation_cannot_exceed_agent_manifest(self) -> None:
        created = self.plane.credentials.create_managed_connection(
            provider_id="generic-api", owner_principal_id="user-123",
            account_identifier="acme", credential={"value": "secret"},
            principal_type="user", principal_id="user-123", label="too-broad",
            grant_scopes=["repositories.delete"], allowed_methods=["DELETE"],
            path_patterns=["/repos/acme/*"], ttl_seconds=300,
            reason="Invalid broad delegation", actor="control-plane-admin",
        )
        with self.assertRaisesRegex(CredentialError, "exceed the agent manifest"):
            self.plane.credentials.delegate_grant(
                created["grant"]["grant_id"], "github-agent", "user-123",
                "Should be rejected",
            )

    def test_oauth_provider_scope_allowlist_fails_closed(self) -> None:
        self.plane.secrets.store("github-client-secret", "client-secret", "admin")
        self.plane.credentials.register_github_provider(
            client_id="github-client-id", client_secret_alias="github-client-secret",
            default_scopes=[], owner="admin",
        )
        with self.assertRaisesRegex(CredentialError, "exceed provider configuration"):
            self.plane.credentials.start_github_connect(
                principal_id="user-123", agent_id="github-agent", label="work",
                provider_scopes=["repo"], grant_scopes=["issues.create"],
                allowed_methods=["POST"], path_patterns=["/repos/acme/*"],
                ttl_seconds=300, reason="Must fail closed",
            )

    @patch("control_plane.credentials.requests.delete")
    @patch("control_plane.credentials.requests.get")
    @patch("control_plane.credentials.requests.post")
    def test_github_disconnect_revokes_provider_token_before_local_custody(
        self, post: Mock, get: Mock, delete: Mock,
    ) -> None:
        self.plane.secrets.store("github-client-secret", "client-secret", "admin")
        self.plane.credentials.register_github_provider(
            client_id="github-client-id", client_secret_alias="github-client-secret",
            default_scopes=["repo"], owner="admin",
        )
        started = self.plane.credentials.start_github_connect(
            principal_id="user-123", agent_id="github-agent", label="revoke-test",
            provider_scopes=["repo"], grant_scopes=["issues.create"],
            allowed_methods=["POST"], path_patterns=["/repos/acme/*"],
            ttl_seconds=300, reason="Test provider revocation",
        )
        state = parse_qs(urlparse(started["connect_url"]).query)["state"][0]
        token_response = Mock()
        token_response.json.return_value = {
            "access_token": "github-token-to-revoke", "scope": "repo"
        }
        token_response.raise_for_status.return_value = None
        post.return_value = token_response
        identity_response = Mock()
        identity_response.json.return_value = {"id": 42, "login": "octocat"}
        identity_response.raise_for_status.return_value = None
        get.return_value = identity_response
        connected = self.plane.credentials.complete_github_connect(
            code="oauth-code", state=state
        )
        connection_id = connected["connection"]["connection_id"]
        delete.return_value.status_code = 500
        delete.return_value.raise_for_status.side_effect = requests.HTTPError("provider down")
        with self.assertRaisesRegex(CredentialError, "provider-side token revocation"):
            self.plane.credentials.revoke_connection(
                connection_id, "user-123", "Disconnect GitHub"
            )
        self.assertEqual(
            "active", self.plane.credentials.connection(connection_id)["status"]
        )

        delete.return_value.status_code = 204
        delete.return_value.raise_for_status.side_effect = None
        self.plane.credentials.revoke_connection(
            connection_id, "user-123", "Disconnect GitHub"
        )
        self.assertEqual(
            "https://api.github.com/applications/github-client-id/token",
            delete.call_args.args[0],
        )
        self.assertEqual(
            {"access_token": "github-token-to-revoke"},
            delete.call_args.kwargs["json"],
        )
        self.assertEqual(
            "revoked", self.plane.credentials.connection(connection_id)["status"]
        )
        self.assertNotIn(
            "github-token-to-revoke", json.dumps(self.plane.audit.events(limit=500))
        )

    @patch("control_plane.credentials.requests.delete")
    def test_managed_disconnect_is_local_and_skips_provider_api(self, delete: Mock) -> None:
        connection = self.plane.credentials.create_managed_connection(
            provider_id="generic-api", owner_principal_id="user-123",
            account_identifier="acme", credential={"value": "secret"},
            principal_type="user", principal_id="user-123", label="managed",
            grant_scopes=["issues.create"], allowed_methods=["POST"],
            path_patterns=["/repos/acme/*"], ttl_seconds=300,
            reason="Managed credential", actor="admin",
        )
        # Managed credentials have no provider revocation protocol and should
        # revoke locally without making an outbound call.
        connection_id = connection["connection"]["connection_id"]
        self.plane.credentials.revoke_connection(
            connection_id, "user-123", "Disconnect managed credential"
        )
        delete.assert_not_called()
        self.assertEqual(
            "revoked", self.plane.credentials.connection(connection_id)["status"]
        )


if __name__ == "__main__":
    unittest.main()
