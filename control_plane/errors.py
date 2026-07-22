"""Stable public error contract shared by the API and SDKs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ErrorCode = Literal[
    "invalid_request",
    "invalid_scope",
    "invalid_key",
    "expired_session",
    "policy_denied",
    "approval_required",
    "revoked",
    "not_found",
    "conflict",
    "unauthorized",
    "forbidden",
    "provider_error",
    "unavailable",
]


@dataclass(frozen=True)
class ErrorDefinition:
    status: int
    retryable: bool = False


ERRORS: dict[str, ErrorDefinition] = {
    "invalid_request": ErrorDefinition(400),
    "invalid_scope": ErrorDefinition(422),
    "invalid_key": ErrorDefinition(401),
    "expired_session": ErrorDefinition(410),
    "policy_denied": ErrorDefinition(403),
    "approval_required": ErrorDefinition(202),
    "revoked": ErrorDefinition(401),
    "not_found": ErrorDefinition(404),
    "conflict": ErrorDefinition(409),
    "unauthorized": ErrorDefinition(401),
    "forbidden": ErrorDefinition(403),
    "provider_error": ErrorDefinition(502, True),
    "unavailable": ErrorDefinition(503, True),
}


class WardenAPIError(RuntimeError):
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        definition = ERRORS[code]
        self.code = code
        self.detail = detail
        self.status = definition.status
        self.retryable = definition.retryable

    def body(self, request_id: str | None = None) -> dict:
        return {
            "error": {
                "code": self.code,
                "detail": self.detail,
                "retryable": self.retryable,
                "request_id": request_id,
            }
        }


def classify(detail: str, *, status: int = 400) -> WardenAPIError:
    """Map legacy domain exceptions into the closed public contract."""
    lowered = detail.lower()
    if "approval" in lowered and ("required" in lowered or "pending" in lowered):
        return WardenAPIError("approval_required", detail)
    if "revok" in lowered:
        return WardenAPIError("revoked", detail)
    if "expired" in lowered or "single-use" in lowered or "already used" in lowered:
        return WardenAPIError("expired_session", detail)
    if "scope" in lowered:
        return WardenAPIError("invalid_scope", detail)
    if "not found" in lowered or "unknown" in lowered:
        return WardenAPIError("not_found", detail)
    if "already" in lowered or "conflict" in lowered:
        return WardenAPIError("conflict", detail)
    if "policy" in lowered or "denied" in lowered or "not permitted" in lowered:
        return WardenAPIError("policy_denied", detail)
    if status == 401:
        return WardenAPIError("unauthorized", detail)
    if status == 403:
        return WardenAPIError("forbidden", detail)
    if status == 404:
        return WardenAPIError("not_found", detail)
    return WardenAPIError("invalid_request", detail)
