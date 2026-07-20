"""An agent runtime whose only side effect passes through Warden."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .content import DraftGenerator
from .models import BlogBrief, BlogDraft


class ActionGateway(Protocol):
    def execute(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PublishingAuthority:
    capability_token: str
    runtime_proof: str
    task_id: str
    connector_id: str
    resource: str
    environment: str
    grant_id: str | None = None
    approval_id: str | None = None


@dataclass(frozen=True)
class BlogRunResult:
    draft: BlogDraft
    action: dict[str, Any]


class BlogAutomationAgent:
    """Plan a post, then ask Warden to authorize and execute publication."""

    action = "blog.publish_post"

    def __init__(self, generator: DraftGenerator, gateway: ActionGateway):
        self.generator = generator
        self.gateway = gateway

    def run(self, brief: BlogBrief, authority: PublishingAuthority) -> BlogRunResult:
        draft = self.generator.generate(brief)
        action = self.gateway.execute(
            capability_token=authority.capability_token,
            runtime_proof=authority.runtime_proof,
            task_id=authority.task_id,
            connector_id=authority.connector_id,
            action=self.action,
            resource=authority.resource,
            environment=authority.environment,
            parameters={
                "title": draft.title,
                "slug": draft.slug,
                "excerpt": draft.excerpt,
                "content": draft.content,
                "status": draft.status,
            },
            data_classification="public",
            approval_id=authority.approval_id,
            grant_id=authority.grant_id,
            risk_signals={"content_source": "owner_brief"},
        )
        return BlogRunResult(draft=draft, action=action)
