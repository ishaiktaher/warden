from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from control_plane.config import Settings
from control_plane.connectors import ConnectorDispatcher
from control_plane.database import Database
from control_plane.schemas import ConnectorManifest
from examples.reference_integrations import (
    github_issues_connector, slack_message_connector, vouchins_blog_connector,
)


class ReferenceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        settings = Settings(
            database_path=root / "warden.db", data_dir=root, issuer="test",
            audience="test", admin_key="admin", environment="test",
            allowed_egress_hosts=("api.github.com", "slack.com", "www.vouchins.com"),
        )
        self.dispatcher = ConnectorDispatcher(Database(settings.database_path), settings)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_three_reference_manifests_are_strictly_valid(self) -> None:
        manifests = (
            github_issues_connector("vouchins/warden"),
            slack_message_connector("T-VOUCHINS"),
            vouchins_blog_connector("https://www.vouchins.com/api/admin/blog"),
        )
        for manifest in manifests:
            self.assertTrue(ConnectorManifest(**manifest).grant_required)
            self.assertEqual("parameters", manifest["credential_config"]["request_body_mode"])

    def test_provider_native_payloads_cross_the_hardened_dispatcher(self) -> None:
        cases = (
            (github_issues_connector("vouchins/warden"), {"title": "Agent-created issue", "body": "Evidence"}),
            (slack_message_connector("T-VOUCHINS"), {"channel": "C-ALERTS", "text": "Warden allowed this message"}),
            (vouchins_blog_connector("https://www.vouchins.com/api/admin/blog"), {"title": "Bounded agents", "content": "Draft", "status": "draft"}),
        )
        for manifest, payload in cases:
            connector = {**manifest, "credential_config": json.dumps(manifest["credential_config"])}
            with self.subTest(connector=manifest["connector_id"]), patch.object(
                self.dispatcher, "_validate_public_host", return_value=("203.0.113.10",)
            ), patch.object(
                self.dispatcher, "_pinned_json_request", return_value={"ok": True}
            ) as request:
                result = self.dispatcher.execute(
                    connector, manifest["resource_patterns"][0].replace("*", "target"),
                    payload, {"access_token": "provider-secret"},
                )
                self.assertEqual({"ok": True}, result)
                self.assertEqual(payload, request.call_args.kwargs["json_body"])
                self.assertEqual("Bearer provider-secret", request.call_args.kwargs["headers"]["Authorization"])


if __name__ == "__main__":
    unittest.main()
