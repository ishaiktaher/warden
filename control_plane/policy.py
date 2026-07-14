"""Policy decision point combining identity, capability, approval and risk rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any

from .database import Database
from .resources import ResourceError, resource_matches


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    approval_required: bool = False
    layers: tuple[str, ...] = ()


DEFAULT_RULES: dict[str, Any] = {
    "deny_tools": ["shell"],
    "approval_for_production_writes": True,
    "approval_for_risk_tiers": ["high", "critical"],
    "sensitive_data_scope": "data:sensitive",
    "max_anomaly_score": 0.8,
    "allowed_geographies": [],
    "deny_actions": [],
    "require_grants_for_external": False,
}


class PolicyEngine:
    def __init__(self, database: Database):
        self.database = database

    def active_rules(
        self, *, tenant_id: str, agent_id: str,
        connector_id: str, grant_id: str | None,
    ) -> tuple[dict[str, Any], tuple[str, ...]] | None:
        rows = self.database.all(
            """SELECT policy_id,layer,target_id,rules FROM policy_bundles
            WHERE status='active' ORDER BY version"""
        )
        targets = {
            "platform": {"*"}, "tenant": {tenant_id}, "agent": {agent_id},
            "connector": {connector_id}, "grant": {grant_id} if grant_id else set(),
        }
        applicable = [
            row for row in rows
            if row["layer"] in targets and row["target_id"] in targets[row["layer"]]
        ]
        if not applicable:
            return None
        merged = dict(DEFAULT_RULES)
        deny_tools = set(merged["deny_tools"])
        deny_actions: set[str] = set()
        approval_tiers = set(merged["approval_for_risk_tiers"])
        geography_sets: list[set[str]] = []
        max_anomaly = float(merged["max_anomaly_score"])
        layers: list[str] = []
        for row in applicable:
            rules = json.loads(row["rules"])
            layers.append(f"{row['layer']}:{row['target_id']}:{row['policy_id']}")
            deny_tools.update(rules.get("deny_tools", []))
            deny_actions.update(rules.get("deny_actions", []))
            approval_tiers.update(rules.get("approval_for_risk_tiers", []))
            if rules.get("allowed_geographies"):
                geography_sets.append(set(rules["allowed_geographies"]))
            if "max_anomaly_score" in rules:
                max_anomaly = min(max_anomaly, float(rules["max_anomaly_score"]))
            merged["approval_for_production_writes"] = bool(
                merged["approval_for_production_writes"]
                or rules.get("approval_for_production_writes", False)
            )
            merged["require_grants_for_external"] = bool(
                merged["require_grants_for_external"]
                or rules.get("require_grants_for_external", False)
            )
        merged["deny_tools"] = sorted(deny_tools)
        merged["deny_actions"] = sorted(deny_actions)
        merged["approval_for_risk_tiers"] = sorted(approval_tiers)
        merged["max_anomaly_score"] = max_anomaly
        if geography_sets:
            merged["allowed_geographies"] = sorted(set.intersection(*geography_sets))
        return merged, tuple(layers)

    def decide(
        self,
        *,
        agent: Any,
        run: Any,
        connector: Any,
        claims: dict[str, Any],
        action: str,
        resource: str,
        data_classification: str,
        environment: str,
        approval_id: str | None,
        risk_signals: dict[str, Any],
        grant: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        active = self.active_rules(
            tenant_id=connector["owner"], agent_id=agent["agent_id"],
            connector_id=connector["connector_id"],
            grant_id=grant["grant_id"] if grant else None,
        )
        if active is None:
            return PolicyDecision(False, "No active policy bundle")
        rules, layers = active
        def deny(reason: str) -> PolicyDecision:
            return PolicyDecision(False, reason, layers=layers)
        if agent["status"] != "active":
            return deny("Agent is not active")
        if run["status"] != "active" or run["revoked_at"]:
            return deny("Runtime session is not active")
        if connector["status"] != "active":
            return deny("Connector is not active")
        if environment != run["environment"] or environment != agent["environment"]:
            return deny("Environment mismatch")
        if connector["tool"] in rules["deny_tools"]:
            return deny("Tool is denied by policy")
        if action in rules["deny_actions"]:
            return deny("Action is denied by layered policy")
        if connector["tool"] not in json.loads(agent["allowed_tools"]):
            return deny("Tool is not allowed for agent")
        if action not in json.loads(agent["allowed_actions"]):
            return deny("Action is not allowed for agent")
        if data_classification not in json.loads(agent["allowed_data_classifications"]):
            return deny("Data classification is not allowed for agent")
        if action not in claims["scopes"]:
            return deny("Action is outside capability scope")
        if connector["grant_required"] and not grant:
            return deny("Connector requires a credential grant")
        if rules["require_grants_for_external"] and connector["adapter_type"] in {
            "rest", "mcp_upstream", "a2a_upstream"
        } and not grant:
            return deny("Layered policy requires a credential grant")
        try:
            capability_match = any(
                resource_matches(resource, pattern) for pattern in claims["resources"]
            )
            connector_match = any(
                resource_matches(resource, pattern)
                for pattern in json.loads(connector["resource_patterns"])
            )
        except ResourceError as exc:
            return deny(str(exc))
        if not capability_match:
            return deny("Resource is outside capability scope")
        if not connector_match:
            return deny("Resource is outside connector allowlist")
        required_scopes = set(json.loads(connector["required_scopes"]))
        if not required_scopes.issubset(set(claims["scopes"])):
            return deny("Connector scope requirement is not satisfied")
        if data_classification == "sensitive" and rules["sensitive_data_scope"] not in claims["scopes"]:
            return deny("Sensitive data scope is required")
        try:
            anomaly_score = float(risk_signals.get("anomaly_score", 0))
        except (TypeError, ValueError):
            return deny("Invalid anomaly risk signal")
        if anomaly_score > float(rules["max_anomaly_score"]):
            return deny("Risk anomaly threshold exceeded")
        allowed_geographies = rules.get("allowed_geographies") or []
        geography = risk_signals.get("geography")
        if allowed_geographies and geography not in allowed_geographies:
            return deny("Geography is not allowed")

        is_write = not action.endswith((".read", ".list", ".draft"))
        needs_approval = (
            (rules["approval_for_production_writes"] and environment == "prod" and is_write)
            or connector["risk_tier"] in set(rules["approval_for_risk_tiers"])
        )
        if needs_approval and not self._approved(
            approval_id, run["run_id"], agent["agent_id"], action, resource
        ):
            return PolicyDecision(False, "Human approval is required", True, layers)
        return PolicyDecision(True, "Policy allowed", layers=layers)

    def _approved(
        self,
        approval_id: str | None,
        run_id: str,
        agent_id: str,
        action: str,
        resource: str,
    ) -> bool:
        if not approval_id:
            return False
        row = self.database.one(
            """SELECT * FROM approvals WHERE approval_id=? AND run_id=? AND agent_id=?
            AND action=? AND resource=? AND status='approved'""",
            (approval_id, run_id, agent_id, action, resource),
        )
        if not row:
            return False
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
            return False
        return True
