from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from control_plane.config import Settings
from control_plane.connectors import ConnectorDispatcher, ConnectorError
from control_plane.database import Database


class ConnectorBodyModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.settings = Settings(
            database_path=root / "warden.db", data_dir=root,
            issuer="test", audience="test", admin_key="admin",
            environment="test", allowed_egress_hosts=("cms.example.com",),
        )
        self.dispatcher = ConnectorDispatcher(
            Database(self.settings.database_path), self.settings
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_parameters_mode_sends_native_json_body(self) -> None:
        connector = {
            "adapter_type": "rest", "endpoint": "https://cms.example.com/posts",
            "http_method": "POST", "action": "blog.publish_post",
            "credential_mode": "basic",
            "credential_config": '{"request_body_mode":"parameters"}',
        }
        parameters = {"title": "Bounded agents", "status": "draft"}
        with patch.object(
            self.dispatcher, "_validate_public_host", return_value=("203.0.113.10",)
        ), patch.object(
            self.dispatcher, "_pinned_json_request", return_value={"id": 42}
        ) as request:
            result = self.dispatcher.execute(
                connector, "cms://vouchins/blog/bounded-agents", parameters,
                {"username": "editor", "password": "application-password"},
            )
        self.assertEqual({"id": 42}, result)
        self.assertEqual(parameters, request.call_args.kwargs["json_body"])
        self.assertTrue(
            request.call_args.kwargs["headers"]["Authorization"].startswith("Basic ")
        )

    def test_unknown_body_mode_fails_closed(self) -> None:
        connector = {
            "adapter_type": "rest", "endpoint": "https://cms.example.com/posts",
            "http_method": "POST", "action": "blog.publish_post",
            "credential_mode": "bearer",
            "credential_config": '{"request_body_mode":"raw_unchecked"}',
        }
        with patch.object(
            self.dispatcher, "_validate_public_host", return_value=("203.0.113.10",)
        ):
            with self.assertRaisesRegex(ConnectorError, "body mode"):
                self.dispatcher.execute(connector, "cms://vouchins/blog/post", {}, None)


if __name__ == "__main__":
    unittest.main()
