"""Manifests and local bootstrap helpers for the Vouchins blog agent."""

from __future__ import annotations

from typing import Any

from control_plane.service import ControlPlane


AGENT_ID = "vouchins-blog-publisher"
ACTION = "blog.publish_post"
LOCAL_CONNECTOR_ID = "vouchins-blog-local"


def agent_manifest(
    environment: str = "test", owner: str = "vouchins-content",
    agent_id: str = AGENT_ID,
) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "name": "Vouchins Blog Publisher",
        "owner": owner,
        "purpose": "Create and publish bounded Vouchins blog posts through Warden",
        "model_provider": "owner-supplied",
        "agent_version": "1.0.0",
        "environment": environment,
        "risk_tier": "high",
        "allowed_tools": ["cms"],
        "allowed_actions": [ACTION],
        "allowed_data_classifications": ["public"],
        "max_delegation_depth": 0,
        "approved_parents": [],
        "approved_children": [],
    }


def local_connector(owner: str = "vouchins-content") -> dict[str, Any]:
    return {
        "connector_id": LOCAL_CONNECTOR_ID,
        "tool": "cms",
        "action": ACTION,
        "adapter_type": "local_emulator",
        "resource_patterns": ["cms://vouchins/blog/*"],
        "required_scopes": [ACTION],
        "owner": owner,
        "risk_tier": "low",
        "rate_limit_per_minute": 10,
    }


def wordpress_connector(
    endpoint: str, owner: str = "vouchins-content",
    connector_id: str = "vouchins-blog-wordpress",
) -> dict[str, Any]:
    """Return a connector for a WordPress-compatible JSON posts endpoint.

    Credentials must be provisioned as a Warden connection/grant. They are not
    accepted by this helper and must never be placed in the agent environment.
    """
    return {
        "connector_id": connector_id,
        "tool": "cms",
        "action": ACTION,
        "adapter_type": "rest",
        "endpoint": endpoint,
        "http_method": "POST",
        "resource_patterns": ["cms://vouchins/blog/*"],
        "required_scopes": [ACTION],
        "owner": owner,
        "risk_tier": "high",
        "rate_limit_per_minute": 5,
        "credential_mode": "basic",
        "credential_config": {
            "request_body_mode": "parameters",
        },
        "grant_required": True,
    }


def bootstrap_local(plane: ControlPlane, actor: str = "reference-bootstrap") -> None:
    """Install an idempotent, non-production reference configuration."""
    if plane.settings.production:
        raise RuntimeError("Local blog demo bootstrap is disabled in production")
    environment = plane.settings.environment
    if not plane.database.one("SELECT agent_id FROM agents WHERE agent_id=?", (AGENT_ID,)):
        plane.register_agent(agent_manifest(environment), actor)
        plane.approve_agent(AGENT_ID, actor)
    plane.register_connector(local_connector(), actor)
    if not plane.database.one("SELECT policy_id FROM policy_bundles WHERE status='active'"):
        plane.seed_policy({}, actor)
