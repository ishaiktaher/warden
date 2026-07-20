from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from uuid import uuid4

from control_plane.config import Settings
from control_plane.service import ControlPlane
from examples.blog_agent import (
    BlogAutomationAgent, BlogBrief, PublishingAuthority, TemplateDraftGenerator,
)
from examples.blog_agent.setup import ACTION, AGENT_ID, LOCAL_CONNECTOR_ID, bootstrap_local


class _Gateway:
    def __init__(self, plane: ControlPlane):
        self.plane = plane

    def execute(self, **request: Any) -> dict[str, Any]:
        request["token"] = request.pop("capability_token")
        request["request_nonce"] = str(uuid4())
        return self.plane.execute_action(**request)


class BlogAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        root = Path(self.temp.name)
        self.plane = ControlPlane(Settings(
            database_path=root / "warden.db", data_dir=root,
            issuer="test-issuer", audience="test-gateway", admin_key="admin",
            environment="test", allowed_egress_hosts=(),
        ))
        bootstrap_local(self.plane)
        self.run = self.plane.create_run(
            "content-owner", AGENT_ID, "Publish one bounded article", "test",
        )
        self.task = self.plane.create_task(self.run["run_id"], "Create the article")
        self.resource = "cms://vouchins/blog/agent-authorization"
        self.token, _ = self.plane.issue_capability(
            run_id=self.run["run_id"], scopes=[ACTION],
            resources=[self.resource], ttl_seconds=300,
        )
        self.agent = BlogAutomationAgent(TemplateDraftGenerator(), _Gateway(self.plane))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _authority(self, resource: str | None = None) -> PublishingAuthority:
        return PublishingAuthority(
            capability_token=self.token,
            runtime_proof=self.run["runtime_proof"],
            task_id=self.task["task_id"], connector_id=LOCAL_CONNECTOR_ID,
            resource=resource or self.resource, environment="test",
        )

    def test_agent_publishes_only_through_warden(self) -> None:
        result = self.agent.run(
            BlogBrief("Identity and authorization for AI agents"), self._authority(),
        )
        self.assertEqual("executed", result.action["status"])
        row = self.plane.database.one(
            "SELECT value FROM emulator_resources WHERE resource=?", (self.resource,),
        )
        self.assertIsNotNone(row)
        self.assertIn("Identity and authorization", row["value"])
        events = self.plane.database.all(
            "SELECT event_type FROM audit_events ORDER BY sequence"
        )
        self.assertIn("policy.allowed", [event["event_type"] for event in events])
        self.assertIn("action.executed", [event["event_type"] for event in events])

    def test_out_of_scope_publish_is_denied_before_connector(self) -> None:
        result = self.agent.run(
            BlogBrief("A post an attacker tries to redirect"),
            self._authority("cms://attacker/blog/stolen-post"),
        )
        self.assertEqual("denied", result.action["status"])
        self.assertIn("outside capability", result.action["reason"].lower())
        self.assertEqual(0, len(self.plane.database.all("SELECT * FROM tool_calls")))
        self.assertIsNone(self.plane.database.one(
            "SELECT value FROM emulator_resources WHERE resource=?",
            ("cms://attacker/blog/stolen-post",),
        ))

    def test_untrusted_text_is_rendered_as_content_not_markup(self) -> None:
        draft = TemplateDraftGenerator().generate(
            BlogBrief("AI safety <script>alert('x')</script>"),
        )
        self.assertNotIn("<script>", draft.content)
        self.assertIn("&lt;script&gt;", draft.content)


if __name__ == "__main__":
    unittest.main()
