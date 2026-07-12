"""HMAC-signed, expiring, single-use capability tokens."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import time
from typing import Any
from uuid import UUID, uuid4

from dotenv import load_dotenv
from supabase import Client, create_client

from audit import record_audit_event
from identity.registry import get_agent


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SIGNATURE_SIZE = hashlib.sha256().digest_size


@dataclass(frozen=True)
class VerifyResult:
    valid: bool
    reason: str
    grant_id: str | None


def _signing_key() -> bytes:
    load_dotenv(PROJECT_ROOT / ".env")
    value = os.getenv("CAPABILITY_SIGNING_KEY", "").strip()
    if not value:
        raise RuntimeError("CAPABILITY_SIGNING_KEY is not configured")
    return value.encode()


def _supabase_client() -> Client:
    load_dotenv(PROJECT_ROOT / ".env")
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip()
    if not url or not key:
        raise RuntimeError("Supabase capability storage is not configured")
    return create_client(url, key)


def issue_capability(
    agent_id: str,
    action: str,
    max_spend: float,
    currency: str,
    resource: str,
    ttl_seconds: int,
) -> str:
    """Return one URL-safe base64 token containing payload and HMAC signature."""
    get_agent(agent_id)
    if not action or not resource:
        raise ValueError("action and resource must not be empty")
    if isinstance(max_spend, bool) or not isinstance(max_spend, (int, float)):
        raise ValueError("max_spend must be numeric")
    if not math.isfinite(float(max_spend)) or float(max_spend) < 0:
        raise ValueError("max_spend must be a non-negative finite number")
    normalized_currency = currency.strip().upper()
    if len(normalized_currency) != 3 or not normalized_currency.isalpha():
        raise ValueError("currency must be a three-letter code")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")

    issued_at = int(time.time())
    payload = {
        "agent_id": agent_id,
        "action": action,
        "max_spend": float(max_spend),
        "currency": normalized_currency,
        "resource": resource,
        "issued_at": issued_at,
        "expiry": issued_at + ttl_seconds,
        "grant_id": str(uuid4()),
        "single_use": True,
    }
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode()
    signature = hmac.new(_signing_key(), payload_bytes, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(payload_bytes + b"." + signature).decode()
    record_audit_event(
        "warden",
        "capability_issued",
        {
            "status": "success",
            "grant_id": payload["grant_id"],
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "currency": normalized_currency,
            "max_spend": float(max_spend),
        },
    )
    return token


def _reject(reason: str, grant_id: str | None) -> VerifyResult:
    record_audit_event(
        "warden",
        "capability_rejected",
        {"status": "blocked", "reason": reason, **({"grant_id": grant_id} if grant_id else {})},
    )
    return VerifyResult(False, reason, grant_id)


def _consume_grant(grant_id: str) -> bool:
    """Atomically insert once; ignored duplicate means the grant was consumed."""
    response = (
        _supabase_client()
        .table("consumed_grants")
        .upsert(
            {"grant_id": grant_id},
            on_conflict="grant_id",
            ignore_duplicates=True,
        )
        .execute()
    )
    return bool(response.data)


def _signed_payload(token: str) -> dict[str, Any]:
    """Return claims only when the token signature is valid; do not consume."""
    raw = base64.urlsafe_b64decode(token.encode())
    if len(raw) <= SIGNATURE_SIZE + 1 or raw[-(SIGNATURE_SIZE + 1)] != ord("."):
        raise ValueError("Invalid capability signature")
    payload_bytes = raw[: -(SIGNATURE_SIZE + 1)]
    supplied_signature = raw[-SIGNATURE_SIZE:]
    expected_signature = hmac.new(_signing_key(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise ValueError("Invalid capability signature")
    payload = json.loads(payload_bytes)
    if not isinstance(payload, dict):
        raise ValueError("Invalid capability signature")
    return payload


def capability_claims(token: str) -> dict[str, Any]:
    """Read signed claims after verification without exposing the signing key."""
    return dict(_signed_payload(token))


def verify_capability(
    token: str,
    expected_agent_id: str,
    expected_action: str,
    expected_resource: str,
) -> VerifyResult:
    """Verify claims in order and atomically consume a valid grant."""
    grant_id: str | None = None
    try:
        payload = _signed_payload(token)
        candidate_grant = payload.get("grant_id")
        if isinstance(candidate_grant, str):
            UUID(candidate_grant)
            grant_id = candidate_grant
    except (ValueError, TypeError, json.JSONDecodeError, RuntimeError):
        return _reject("Invalid capability signature", None)

    if grant_id is None or payload.get("single_use") is not True:
        return _reject("Invalid capability signature", None)
    expiry = payload.get("expiry")
    if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
        return _reject("Invalid capability signature", grant_id)
    if time.time() >= float(expiry):
        return _reject("Capability expired", grant_id)
    if payload.get("agent_id") != expected_agent_id:
        return _reject("Capability agent identity mismatch", grant_id)
    if payload.get("action") != expected_action:
        return _reject("Capability action mismatch", grant_id)
    if payload.get("resource") != expected_resource:
        return _reject("Capability resource mismatch", grant_id)

    try:
        consumed = _consume_grant(grant_id)
    except Exception:
        return _reject("Capability consumption unavailable", grant_id)
    if not consumed:
        return _reject("Capability already consumed", grant_id)

    record_audit_event(
        "warden",
        "capability_verified",
        {"status": "success", "grant_id": grant_id, "agent_id": expected_agent_id},
    )
    record_audit_event(
        "warden",
        "capability_consumed",
        {"status": "success", "grant_id": grant_id},
    )
    return VerifyResult(True, "Capability verified", grant_id)
