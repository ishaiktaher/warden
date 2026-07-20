"""Content-planning boundary for the reference agent.

The included generator is deterministic so CI and live Warden demonstrations do
not depend on an LLM vendor. Production owners can implement ``DraftGenerator``
with their model runtime; the publishing authority remains unchanged.
"""

from __future__ import annotations

from html import escape
from typing import Protocol

from .models import BlogBrief, BlogDraft, slugify


class DraftGenerator(Protocol):
    def generate(self, brief: BlogBrief) -> BlogDraft: ...


class TemplateDraftGenerator:
    """Safe offline generator used by the executable reference scenario."""

    def generate(self, brief: BlogBrief) -> BlogDraft:
        topic = escape(brief.topic)
        audience = escape(brief.audience)
        points = brief.key_points or (
            "Give every agent a stable runtime identity.",
            "Authorize exact actions and resources with short-lived capabilities.",
            "Keep credentials behind the action gateway and record every decision.",
        )
        bullets = "".join(f"<li>{escape(point)}</li>" for point in points)
        title = f"{brief.topic}: a practical guide"
        content = (
            f"<p>{topic} matters to {audience}. Autonomous software needs useful "
            "authority, but that authority must be explicit, bounded and observable.</p>"
            f"<h2>What teams should implement</h2><ul>{bullets}</ul>"
            "<h2>How Warden helps</h2><p>Warden evaluates identity, capability, "
            "policy, credential grants and risk before a connector can create an "
            "external side effect. The agent never receives the downstream secret.</p>"
            "<p>Start with one narrow workflow, inspect its audit trail, and expand "
            "authority only after repeated successful evaluations.</p>"
        )
        return BlogDraft(
            title=title,
            slug=slugify(title),
            excerpt=f"A practical introduction to {brief.topic} for {brief.audience}.",
            content=content,
            status=brief.publish_status,
        )
