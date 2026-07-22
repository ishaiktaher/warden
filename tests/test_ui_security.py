from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
import unittest

from control_plane.observability import UI_SCRIPT_SHA256


class UiSecurityTests(unittest.TestCase):
    def test_management_script_matches_content_security_policy_hash(self) -> None:
        html = (Path(__file__).parents[1] / "ui" / "index.html").read_text()
        script = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
        self.assertIsNotNone(script)
        digest = base64.b64encode(
            hashlib.sha256(script.group(1).encode()).digest()
        ).decode()
        self.assertEqual(UI_SCRIPT_SHA256, digest)

    def test_connect_widget_accepts_only_backend_session_context(self) -> None:
        widget = (Path(__file__).parents[1] / "ui" / "warden-connect.js").read_text()
        self.assertIn('getAttribute("session-token")', widget)
        self.assertIn("event.source !== popup", widget)
        self.assertNotIn("/me/connections", widget)
        self.assertNotIn('getAttribute("principal-id")', widget)
        self.assertNotIn('getAttribute("grant-scopes")', widget)


if __name__ == "__main__":
    unittest.main()
