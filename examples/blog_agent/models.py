"""Validated domain objects for the blog automation agent."""

from __future__ import annotations

from dataclasses import dataclass
import re


class BlogAgentError(ValueError):
    """Raised when an unsafe or incomplete blog task is supplied."""


def _bounded(value: str, name: str, minimum: int, maximum: int) -> str:
    normalized = " ".join(value.split()).strip()
    if not minimum <= len(normalized) <= maximum:
        raise BlogAgentError(f"{name} must contain {minimum}-{maximum} characters")
    return normalized


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not slug:
        raise BlogAgentError("The title cannot produce an empty slug")
    return slug[:100].rstrip("-")


@dataclass(frozen=True)
class BlogBrief:
    topic: str
    audience: str = "technology leaders and AI-agent developers"
    tone: str = "clear, practical and trustworthy"
    key_points: tuple[str, ...] = ()
    publish_status: str = "draft"

    def __post_init__(self) -> None:
        object.__setattr__(self, "topic", _bounded(self.topic, "topic", 3, 175))
        object.__setattr__(self, "audience", _bounded(self.audience, "audience", 3, 200))
        object.__setattr__(self, "tone", _bounded(self.tone, "tone", 3, 100))
        if len(self.key_points) > 12:
            raise BlogAgentError("At most 12 key points are allowed")
        points = tuple(_bounded(point, "key point", 2, 300) for point in self.key_points)
        object.__setattr__(self, "key_points", points)
        if self.publish_status not in {"draft", "publish"}:
            raise BlogAgentError("publish_status must be draft or publish")


@dataclass(frozen=True)
class BlogDraft:
    title: str
    slug: str
    excerpt: str
    content: str
    status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _bounded(self.title, "title", 3, 200))
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", self.slug):
            raise BlogAgentError("slug contains unsupported characters")
        object.__setattr__(self, "excerpt", _bounded(self.excerpt, "excerpt", 10, 500))
        content = self.content.strip()
        if not 50 <= len(content) <= 100_000:
            raise BlogAgentError("content must contain 50-100000 characters")
        object.__setattr__(self, "content", content)
        if self.status not in {"draft", "publish"}:
            raise BlogAgentError("status must be draft or publish")
