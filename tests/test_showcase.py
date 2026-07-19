"""Security and availability checks for the public serverless surface."""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from api.index import app


class ShowcaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_public_pages_and_health_are_available(self) -> None:
        for path in ("/", "/documentation", "/openapi.html", "/showcase.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

        homepage = self.client.get("/")
        self.assertIn("https://www.vouchins.com/images/logo.png", homepage.text)
        self.assertIn('data-scenario="legitimate"', homepage.text)
        self.assertIn('data-scenario="malicious"', homepage.text)
        self.assertIn('<script src="/showcase.js" defer></script>', homepage.text)
        self.assertIn(
            "img-src 'self' data: https://www.vouchins.com",
            homepage.headers["content-security-policy"],
        )
        self.assertIn("script-src 'self'", homepage.headers["content-security-policy"])

        script = self.client.get("/showcase.js")
        self.assertIn("Prompt injection attempts an unauthorized", script.text)
        self.assertIn("Credential never resolved", script.text)

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
