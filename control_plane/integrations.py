"""Versioned integration catalog for Warden's provider-neutral credential gateway.

Catalog entries are not bespoke SDK wrappers. OAuth entries are configured through
Warden's OAuth broker and managed-secret entries use the connector credential
injection modes (bearer, header, multi-header, query, basic, or AWS SigV4). This
keeps authorization policy independent from vendors and permits custom providers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re


CATALOG_VERSION = "2026-07-22"

PROVIDER_CONTRACTS = {
    "github": {
        "authorization_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "api_base_url": "https://api.github.com",
        "identity_url": "https://api.github.com/user",
        "identity_id_field": "id",
        "identity_label_field": "login",
    },
    "google": {
        "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "api_base_url": "https://www.googleapis.com",
        "identity_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "identity_id_field": "sub",
        "identity_label_field": "email",
    },
    "slack": {
        "authorization_url": "https://slack.com/oauth/v2/authorize",
        "token_url": "https://slack.com/api/oauth.v2.access",
        "api_base_url": "https://slack.com/api",
        "identity_url": "https://slack.com/api/users.identity",
        "identity_id_field": "user.id",
        "identity_label_field": "user.name",
    },
    "notion": {
        "authorization_url": "https://api.notion.com/v1/oauth/authorize",
        "token_url": "https://api.notion.com/v1/oauth/token",
        "api_base_url": "https://api.notion.com/v1",
        "identity_url": "https://api.notion.com/v1/users/me",
        "identity_id_field": "id",
        "identity_label_field": "name",
    },
    "stripe": {
        "authorization_url": "https://connect.stripe.com/oauth/authorize",
        "token_url": "https://connect.stripe.com/oauth/token",
        "api_base_url": "https://api.stripe.com/v1",
        "identity_url": "https://api.stripe.com/v1/account",
        "identity_id_field": "id",
        "identity_label_field": "business_profile.name",
    },
}

_VERIFIED: dict[str, tuple[str, str | None]] = {
    **{
        f"oauth:{name}": ("contract_tested", "tests/test_provider_contracts.py")
        for name in PROVIDER_CONTRACTS
    },
    "managed:slack": ("contract_tested", "tests/test_reference_integrations.py"),
    "managed:vouchins-admin-api": (
        "contract_tested",
        "tests/test_reference_integrations.py",
    ),
}


@dataclass(frozen=True)
class Integration:
    integration_id: str
    name: str
    kind: str
    setup_mode: str
    docs_url: str
    credential_modes: tuple[str, ...]
    status: str = "supported"
    verification: str = "catalog_only"
    verified_at: str | None = None
    evidence: str | None = None

    def public(self) -> dict:
        result = asdict(self)
        result["credential_modes"] = list(self.credential_modes)
        return result


def _slug(name: str) -> str:
    aliases = {"Twitter (X)": "twitter-x", "QuickBooks": "quickbooks"}
    if name in aliases:
        return aliases[name]
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


_OAUTH_NAMES = (
    "Acuity Scheduling",
    "Adobe",
    "Aircall",
    "Airtable",
    "Apollo.io",
    "Asana",
    "Atlassian",
    "Attio",
    "Autodesk",
    "Basecamp",
    "Bitbucket",
    "Bitly",
    "Box",
    "Brex",
    "Cal.com",
    "Calendly",
    "Canva",
    "ClickUp",
    "Close",
    "Constant Contact",
    "Contentful",
    "Deel",
    "Dialpad",
    "DigitalOcean",
    "Discord",
    "DocuSign",
    "Dropbox",
    "eBay",
    "Eventbrite",
    "Facebook",
    "Figma",
    "GitHub",
    "Google",
    "HubSpot",
    "Instagram",
    "Linear",
    "LinkedIn",
    "Mailchimp",
    "Mercury",
    "Microsoft",
    "Miro",
    "monday.com",
    "Notion",
    "Outreach",
    "PagerDuty",
    "PayPal",
    "Pinterest",
    "Pipedrive",
    "QuickBooks",
    "Ramp",
    "Reddit",
    "RingCentral",
    "Salesforce",
    "Sentry",
    "Slack",
    "Snapchat",
    "Spotify",
    "Square",
    "Squarespace",
    "Stripe",
    "TikTok",
    "Todoist",
    "Twitter (X)",
    "Typeform",
    "Webex",
    "Webflow",
)

_MANAGED_NAMES = (
    "Airtable",
    "Algolia",
    "AWS",
    "Axiom",
    "Braze",
    "Brevo",
    "Browserbase",
    "Clerk",
    "Cloudflare",
    "Coda",
    "Cursor",
    "Datadog",
    "Discord",
    "Exa",
    "Firecrawl",
    "GitHub",
    "GitLab",
    "Grafana",
    "Granola",
    "Incident.io",
    "Klaviyo",
    "PagerDuty",
    "PostHog",
    "Recharge",
    "Resend",
    "Rootly",
    "SendGrid",
    "Sentry",
    "Shopify",
    "Shortcut",
    "Slack",
    "Stripe",
    "Supabase",
    "Tavily",
    "Terraform",
    "Twilio",
    "Vercel",
    "WhatsApp Business",
    "WorkOS",
    "Vouchins Admin API",
)


def _oauth(name: str) -> Integration:
    slug = _slug(name)
    verification, evidence = _VERIFIED.get(f"oauth:{slug}", ("catalog_only", None))
    return Integration(
        integration_id=f"oauth:{slug}",
        name=name,
        kind="oauth2",
        setup_mode="oauth_provider_configuration",
        docs_url="/documentation#connections-docs",
        credential_modes=("bearer",),
        verification=verification,
        verified_at="2026-07-21" if evidence else None,
        evidence=evidence,
    )


def _managed(name: str) -> Integration:
    slug = _slug(name)
    verification, evidence = _VERIFIED.get(f"managed:{slug}", ("catalog_only", None))
    modes = (
        ("aws_sigv4",)
        if name == "AWS"
        else ("bearer", "custom_header", "multi_header", "query", "basic")
    )
    return Integration(
        integration_id=f"managed:{slug}",
        name=name,
        kind="managed_secret",
        setup_mode="managed_secret_template",
        docs_url="/documentation#connections-docs",
        credential_modes=modes,
        verification=verification,
        verified_at="2026-07-21" if evidence else None,
        evidence=evidence,
    )


INTEGRATIONS = tuple(_oauth(name) for name in _OAUTH_NAMES) + tuple(
    _managed(name) for name in _MANAGED_NAMES
)
_BY_ID = {item.integration_id: item for item in INTEGRATIONS}


def catalog(*, kind: str | None = None, query: str | None = None) -> list[dict]:
    normalized_query = (query or "").strip().lower()
    return [
        item.public()
        for item in INTEGRATIONS
        if (not kind or item.kind == kind)
        and (
            not normalized_query
            or normalized_query in item.name.lower()
            or normalized_query in item.integration_id
        )
    ]


def get_integration(integration_id: str) -> dict | None:
    item = _BY_ID.get(integration_id.lower())
    return item.public() if item else None


def catalog_summary() -> dict:
    oauth = sum(item.kind == "oauth2" for item in INTEGRATIONS)
    managed = sum(item.kind == "managed_secret" for item in INTEGRATIONS)
    contract_tested = sum(
        item.verification in {"contract_tested", "live_verified"}
        for item in INTEGRATIONS
    )
    live_verified = sum(item.verification == "live_verified" for item in INTEGRATIONS)
    return {
        "catalog_version": CATALOG_VERSION,
        "total": len(INTEGRATIONS),
        "oauth2": oauth,
        "managed_secret": managed,
        "contract_tested": contract_tested,
        "live_verified": live_verified,
        "catalog_only": len(INTEGRATIONS) - contract_tested,
        "custom_providers_supported": True,
    }
