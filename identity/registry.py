"""Static hackathon identity registry for Warden's four agents."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    role: str


AGENT_REGISTRY = {
    "orchestrator": AgentIdentity("orchestrator", "coordinates trusted user intent"),
    "discovery": AgentIdentity("discovery", "finds untrusted travel evidence"),
    "booking": AgentIdentity("booking", "presents capabilities for booking actions"),
    "communication": AgentIdentity("communication", "announces sanitized outcomes"),
}


def get_agent(agent_id: str) -> AgentIdentity:
    try:
        return AGENT_REGISTRY[agent_id]
    except KeyError:
        raise ValueError("Unknown agent identity") from None
