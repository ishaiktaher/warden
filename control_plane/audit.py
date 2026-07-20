"""Redacted, hash-chained audit ledger with verification and NDJSON export."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable
from uuid import uuid4

from .database import Database
from .config import Settings
from .providers import audit_provider


GENESIS_HASH = "0" * 64
SENSITIVE_KEY = re.compile(
    r"(authorization|api[_-]?key|secret|password|token|credential|private[_-]?key)",
    re.IGNORECASE,
)
BEARER_VALUE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return BEARER_VALUE.sub("Bearer [REDACTED]", value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


class AuditLedger:
    def __init__(self, database: Database, settings: Settings | None = None):
        self.database = database
        self.settings = settings
        self.anchor_provider = audit_provider(settings) if settings else None

    def append(
        self,
        event_type: str,
        actor: str,
        *,
        principal_id: str | None = None,
        agent_id: str | None = None,
        run_id: str | None = None,
        task_id: str | None = None,
        tool_call_id: str | None = None,
        decision: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": str(uuid4()),
            "timestamp": _now(),
            "event_type": event_type,
            "actor": actor,
            "principal_id": principal_id,
            "agent_id": agent_id,
            "run_id": run_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "decision": decision,
            "payload": redact(payload or {}),
        }
        with self.database.connect() as connection:
            self.database.acquire_audit_lock(connection)
            previous = connection.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous["event_hash"] if previous else GENESIS_HASH
            canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(
                (previous_hash + canonical).encode("utf-8")
            ).hexdigest()
            connection.execute(
                """
                INSERT INTO audit_events(
                  event_id,timestamp,event_type,actor,principal_id,agent_id,
                  run_id,task_id,tool_call_id,decision,payload,previous_hash,event_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event["event_id"], event["timestamp"], event_type, actor,
                    principal_id, agent_id, run_id, task_id, tool_call_id, decision,
                    json.dumps(event["payload"], sort_keys=True, separators=(",", ":")),
                    previous_hash, event_hash,
                ),
            )
        return {**event, "previous_hash": previous_hash, "event_hash": event_hash}

    def events(
        self, *, run_id: str | None = None, principal_id: str | None = None,
        agent_id: str | None = None, event_type: str | None = None,
        decision: str | None = None, action: str | None = None,
        resource: str | None = None, limit: int = 200,
    ) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 5000)
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("run_id", run_id), ("principal_id", principal_id), ("agent_id", agent_id),
            ("event_type", event_type), ("decision", decision),
        ):
            if value:
                clauses.append(f"{column}=?")
                parameters.append(value)
        sql = "SELECT * FROM audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY sequence DESC LIMIT ?"
        parameters.append(limit)
        rows = self.database.all(sql, tuple(parameters))
        rows.reverse()
        events = [self._row(row) for row in rows]
        if action:
            events = [event for event in events if event["payload"].get("action") == action]
        if resource:
            events = [event for event in events if event["payload"].get("resource") == resource]
        return events

    def verify(self) -> dict[str, Any]:
        rows = self.database.all("SELECT * FROM audit_events ORDER BY sequence")
        previous_hash = GENESIS_HASH
        for row in rows:
            event = self._row(row)
            unsigned = {
                key: event[key]
                for key in (
                    "event_id", "timestamp", "event_type", "actor", "principal_id",
                    "agent_id", "run_id", "task_id", "tool_call_id", "decision", "payload",
                )
            }
            canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
            expected = hashlib.sha256((previous_hash + canonical).encode()).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                return {
                    "valid": False,
                    "events_checked": row["sequence"] - 1,
                    "failed_sequence": row["sequence"],
                }
            previous_hash = row["event_hash"]
        return {"valid": True, "events_checked": len(rows), "head_hash": previous_hash}

    def export_ndjson(self, *, run_id: str | None = None) -> Iterable[str]:
        for event in self.events(run_id=run_id, limit=5000):
            yield json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"

    def anchor(self, actor: str, retention_days: int = 365) -> dict[str, Any]:
        """Write the current chain head to an immutable S3 Object Lock object."""
        verification = self.verify()
        if not verification["valid"]:
            raise RuntimeError("Refusing to anchor an invalid audit chain")
        if not self.anchor_provider:
            raise RuntimeError("An audit anchor provider is not configured")
        timestamp = datetime.now(timezone.utc)
        body = json.dumps({
            "anchored_at": timestamp.isoformat(), "actor": actor,
            "events_checked": verification["events_checked"],
            "head_hash": verification["head_hash"],
        }, sort_keys=True, separators=(",", ":")).encode()
        try:
            receipt = self.anchor_provider.anchor(body, retention_days)
        except Exception as exc:
            raise RuntimeError("Immutable audit anchor delivery failed") from exc
        self.append(
            "audit.anchored", actor,
            payload={"provider": self.anchor_provider.name, "receipt": receipt,
                     "head_hash": verification["head_hash"]},
        )
        return {"status": "anchored", "provider": self.anchor_provider.name,
                "receipt": receipt, "head_hash": verification["head_hash"]}

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "actor": row["actor"],
            "principal_id": row["principal_id"],
            "agent_id": row["agent_id"],
            "run_id": row["run_id"],
            "task_id": row["task_id"],
            "tool_call_id": row["tool_call_id"],
            "decision": row["decision"],
            "payload": json.loads(row["payload"]),
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
        }
