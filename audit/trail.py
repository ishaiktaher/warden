"""Write safe agent events without allowing arbitrary context into the log."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_PATH = PROJECT_ROOT / "audit" / "agent_audit.jsonl"
AGENTS = frozenset(
    {"travel_orchestrator", "discovery_agent", "booking_agent", "communication_agent", "warden", "unsafe_demo_proxy"}
)
EVENTS = frozenset(
    {
        "workflow_started",
        "intent_classification_requested",
        "intent_classification_completed",
        "delegation_requested",
        "discovery_requested",
        "discovery_completed",
        "booking_requested",
        "scope_checked",
        "scope_bypassed",
        "booking_completed",
        "announcement_requested",
        "announcement_completed",
        "operation_failed",
        "capability_issued",
        "capability_delegated",
        "capability_verified",
        "capability_rejected",
        "capability_consumed",
    }
)
SAFE_FIELDS = frozenset(
    {
        "status", "amount", "max_spend", "allowed", "result_count", "trust",
        "intent", "grant_id", "agent_id", "action", "resource", "currency", "reason"
    }
)

CAPABILITY_REASONS = frozenset(
    {
        "Invalid capability signature",
        "Capability expired",
        "Capability agent identity mismatch",
        "Capability action mismatch",
        "Capability resource mismatch",
        "Capability consumption unavailable",
        "Capability already consumed",
        "Capability verified",
    }
)


def _run_id() -> str:
    raw = os.getenv("WARDEN_AUDIT_RUN_ID") or os.getenv("HERMES_SESSION_ID") or "local"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _safe_value(name: str, value: Any) -> Any:
    if name in {"amount", "max_spend"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be numeric")
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError(f"{name} must be a non-negative finite number")
        return number
    if name == "result_count":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("result_count must be a non-negative integer")
        return value
    if name == "allowed":
        if not isinstance(value, bool):
            raise ValueError("allowed must be boolean")
        return value
    if name == "status":
        if value not in {"started", "success", "blocked", "error"}:
            raise ValueError("unsupported audit status")
        return value
    if name == "trust":
        if value != "untrusted_external_evidence":
            raise ValueError("unsupported trust classification")
        return value
    if name == "intent":
        if value not in {"flight_booking", "other"}:
            raise ValueError("unsupported intent classification")
        return value
    if name == "grant_id":
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError("invalid capability grant id")
        return value
    if name == "agent_id":
        if value not in {"orchestrator", "discovery", "booking", "communication"}:
            raise ValueError("unsupported capability agent identity")
        return value
    if name == "action":
        if value != "confirm_booking":
            raise ValueError("unsupported capability action")
        return value
    if name == "resource":
        if not isinstance(value, str) or not value.startswith("http://127.0.0.1:8080"):
            raise ValueError("unsupported capability resource")
        return value
    if name == "currency":
        if value != "INR":
            raise ValueError("unsupported capability currency")
        return value
    if name == "reason":
        if value not in CAPABILITY_REASONS:
            raise ValueError("unsupported capability reason")
        return value
    raise ValueError(f"unsafe audit field: {name}")


def record_audit_event(
    agent: str,
    event: str,
    metadata: Mapping[str, Any] | None = None,
    *,
    path: Path | None = None,
) -> dict[str, Any]:
    """Append one allowlisted event and return the exact stored record."""
    if agent not in AGENTS:
        raise ValueError("unsupported audit agent")
    if event not in EVENTS:
        raise ValueError("unsupported audit event")

    supplied = dict(metadata or {})
    unknown = supplied.keys() - SAFE_FIELDS
    if unknown:
        raise ValueError("audit metadata contains non-allowlisted fields")

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "run_id": _run_id(),
        "agent": agent,
        "event": event,
        **{name: _safe_value(name, value) for name, value in supplied.items()},
    }
    audit_path = path or Path(os.getenv("WARDEN_AUDIT_LOG", DEFAULT_AUDIT_PATH))
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    return record
