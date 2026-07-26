"""Security and availability checks for the public serverless surface."""

from __future__ import annotations

import unittest
from html.parser import HTMLParser
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.index import app


class _DocumentationLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(str(values["id"]))
        if tag == "a" and values.get("href") is not None:
            self.hrefs.append(str(values["href"]))


class ShowcaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_public_pages_and_health_are_available(self) -> None:
        for path in ("/", "/design-partner", "/design-partner.js", "/console", "/documentation", "/openapi.html", "/showcase.js", "/proof"):
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
        self.assertIn('href="/design-partner">Become a design partner', homepage.text)
        self.assertNotIn('href="https://www.vouchins.com/contact">Early Access', homepage.text)

        script = self.client.get("/showcase.js")
        self.assertIn("Prompt injection attempts an unauthorized", script.text)
        self.assertIn("Credential never resolved", script.text)

        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["mode"], "read-only")
        proof = self.client.get("/proof").json()
        self.assertGreaterEqual(proof["test_cases"], 60)
        self.assertEqual(7, proof["contract_tested_integrations"])
        self.assertEqual(0, proof["live_verified_integrations"])

    @patch("control_plane.showcase._send_design_partner_email")
    def test_design_partner_application_is_emailed(self, send_email) -> None:
        submission = {
            "name": "Avery Morgan",
            "email": "avery@example.com",
            "company": "Example Labs",
            "role": "VP Engineering",
            "company_size": "51–200",
            "timeline": "Within 3 months",
            "use_case": "We need bounded authorization for production support agents.",
            "website": "",
        }
        response = self.client.post("/api/design-partner", json=submission)
        self.assertEqual(response.status_code, 200)
        self.assertEqual("no-store", response.headers["cache-control"])
        send_email.assert_called_once()
        self.assertEqual("avery@example.com", send_email.call_args.args[0].email)

    def test_design_partner_application_validates_input(self) -> None:
        response = self.client.post(
            "/api/design-partner",
            json={"name": "A", "email": "not-an-email", "website": "spam"},
        )
        self.assertEqual(response.status_code, 422)

    @patch("control_plane.showcase._send_design_partner_email")
    def test_short_use_case_is_accepted(self, send_email) -> None:
        response = self.client.post(
            "/api/design-partner",
            json={
                "name": "Avery Morgan",
                "email": "avery@example.com",
                "company": "Example Labs",
                "role": "Founder",
                "company_size": "1–10",
                "timeline": "Exploring",
                "use_case": "Agents",
                "website": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once()

    @patch.dict(
        "os.environ",
        {
            "WARDEN_SHOWCASE_EMAIL_PROVIDER": "ses",
            "WARDEN_SHOWCASE_EMAIL_FROM": "verified@example.com",
            "WARDEN_SHOWCASE_SES_REGION": "ap-south-1",
        },
        clear=False,
    )
    @patch("boto3.client")
    def test_ses_api_delivery(self, boto_client) -> None:
        from control_plane.showcase import DesignPartnerSubmission, _send_design_partner_email

        ses = MagicMock()
        boto_client.return_value = ses
        submission = DesignPartnerSubmission(
            name="Avery Morgan",
            email="avery@example.com",
            company="Example Labs",
            role="Founder",
            company_size="1–10",
            timeline="Exploring",
            use_case="Production agents",
        )
        _send_design_partner_email(submission)
        boto_client.assert_called_once_with("ses", region_name="ap-south-1")
        sent = ses.send_raw_email.call_args.kwargs
        self.assertEqual(sent["Source"], "verified@example.com")
        self.assertEqual(sent["Destinations"], ["connect@vouchins.com"])

    @patch.dict(
        "os.environ",
        {
            "SES_SMTP_HOST": "email-smtp.us-east-1.amazonaws.com",
            "SES_SMTP_USER": "ses-user",
            "SES_SMTP_PASS": "ses-password",
            "SES_FROM_EMAIL": "connect@vouchins.com",
        },
        clear=True,
    )
    @patch("control_plane.showcase.smtplib.SMTP")
    def test_existing_ses_smtp_environment_is_supported(self, smtp_class) -> None:
        from control_plane.showcase import DesignPartnerSubmission, _send_design_partner_email

        smtp = smtp_class.return_value.__enter__.return_value
        submission = DesignPartnerSubmission(
            name="Avery Morgan",
            email="avery@example.com",
            company="Example Labs",
            role="Founder",
            company_size="1–10",
            timeline="Exploring",
            use_case="Production agents",
        )
        _send_design_partner_email(submission)
        smtp_class.assert_called_once_with(
            "email-smtp.us-east-1.amazonaws.com", 587, timeout=10
        )
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("ses-user", "ses-password")
        smtp.send_message.assert_called_once()

    def test_documentation_has_no_empty_or_broken_internal_links(self) -> None:
        response = self.client.get("/documentation")
        parser = _DocumentationLinks()
        parser.feed(response.text)
        self.assertTrue(parser.hrefs)
        self.assertNotIn("", parser.hrefs)
        for href in parser.hrefs:
            if href.startswith("#"):
                self.assertIn(href[1:], parser.ids, href)
            elif href.startswith("/"):
                self.assertEqual(200, self.client.get(href).status_code, href)

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
