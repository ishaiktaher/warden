"""Run the Vouchins blog agent through the real local Warden gateway."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from control_plane.service import ControlPlane
from examples.blog_agent import (
    BlogAutomationAgent, BlogBrief, PublishingAuthority, TemplateDraftGenerator,
)
from examples.blog_agent.setup import ACTION, AGENT_ID, LOCAL_CONNECTOR_ID, bootstrap_local


class LocalGateway:
    """Adapt the HTTP-shaped agent call to an in-process demo control plane."""

    def __init__(self, plane: ControlPlane):
        self.plane = plane

    def execute(self, **request: Any) -> dict[str, Any]:
        request["token"] = request.pop("capability_token")
        request["request_nonce"] = str(uuid4())
        return self.plane.execute_action(**request)


def main() -> None:
    plane = ControlPlane()
    bootstrap_local(plane)
    run = plane.create_run(
        "vouchins-content-owner", AGENT_ID,
        "Draft a post explaining production authorization for AI agents",
        plane.settings.environment,
    )
    task = plane.create_task(run["run_id"], "Create one Vouchins blog draft")
    resource = "cms://vouchins/blog/production-authorization-for-ai-agents"
    token, claims = plane.issue_capability(
        run_id=run["run_id"], scopes=[ACTION], resources=[resource], ttl_seconds=300,
    )
    authority = PublishingAuthority(
        capability_token=token,
        runtime_proof=run["runtime_proof"],
        task_id=task["task_id"],
        connector_id=LOCAL_CONNECTOR_ID,
        resource=resource,
        environment=plane.settings.environment,
    )
    agent = BlogAutomationAgent(TemplateDraftGenerator(), LocalGateway(plane))
    result = agent.run(
        BlogBrief(
            topic="Production authorization for AI agents",
            key_points=(
                "Bind every action to an agent, human principal and task.",
                "Grant only the exact action and blog resource required.",
                "Keep CMS credentials inside Warden's connector boundary.",
            ),
        ),
        authority,
    )
    print(json.dumps({
        "status": result.action["status"],
        "title": result.draft.title,
        "resource": resource,
        "capability_jti": claims["jti"],
        "tool_call_id": result.action.get("tool_call_id"),
        "audit": plane.audit.verify(),
    }, indent=2))


if __name__ == "__main__":
    main()
