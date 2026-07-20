"""Contract-tested connector manifests for Warden's reference integrations."""

from __future__ import annotations

from typing import Any


def _rest_connector(
    *, connector_id: str, tool: str, action: str, endpoint: str,
    resource_pattern: str, owner: str,
) -> dict[str, Any]:
    return {
        "connector_id": connector_id,
        "tool": tool,
        "action": action,
        "adapter_type": "rest",
        "endpoint": endpoint,
        "http_method": "POST",
        "resource_patterns": [resource_pattern],
        "required_scopes": [action],
        "owner": owner,
        "risk_tier": "medium",
        "rate_limit_per_minute": 30,
        "credential_mode": "bearer",
        "credential_config": {"request_body_mode": "parameters"},
        "grant_required": True,
    }


def github_issues_connector(
    repository: str, owner: str = "engineering",
) -> dict[str, Any]:
    """Create issues in one exact GitHub repository."""
    return _rest_connector(
        connector_id="github-issues", tool="github", action="github.issues.create",
        endpoint=f"https://api.github.com/repos/{repository}/issues",
        resource_pattern=f"github://repo/{repository}", owner=owner,
    )


def slack_message_connector(
    workspace_id: str, owner: str = "communications",
) -> dict[str, Any]:
    """Post messages with a grant restricted to one Slack workspace resource."""
    return _rest_connector(
        connector_id="slack-chat-post", tool="slack", action="slack.chat.post",
        endpoint="https://slack.com/api/chat.postMessage",
        resource_pattern=f"slack://workspace/{workspace_id}/channel/*", owner=owner,
    )


def vouchins_blog_connector(
    endpoint: str, owner: str = "vouchins",
) -> dict[str, Any]:
    """Publish through Vouchins' operator-supplied admin blog endpoint."""
    return _rest_connector(
        connector_id="vouchins-blog-admin", tool="cms", action="blog.publish_post",
        endpoint=endpoint, resource_pattern="cms://vouchins/blog/*", owner=owner,
    )
