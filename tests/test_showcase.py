"""Security and availability checks for the public serverless surface."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from control_plane.showcase import app


class ShowcaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_public_pages_and_health_are_available(self) -> None:
        for path in ("/", "/documentation", "/openapi.html"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["mode"], "read-only")

    def test_control_plane_endpoints_are_not_mounted(self) -> None:
        for method, path in (
            ("get", "/admin/agents"),
            ("post", "/actions/execute"),
            ("post", "/mcp/tools/call"),
            ("post", "/a2a/message:send"),
            ("get", "/openapi.json"),
            ("get", "/docs"),
        ):
            response = getattr(self.client, method)(path)
            self.assertEqual(response.status_code, 404, path)


if __name__ == "__main__":
    unittest.main()
