"""Dependency-free scope checks performed outside the model."""

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScopeCheckResult:
    allowed: bool
    reason: str


def check_scope(requested_amount: float, scope: dict) -> ScopeCheckResult:
    """Check a requested amount against the scope's authorized limit."""
    max_spend = scope["max_spend"]
    allowed_by_scope = requested_amount <= max_spend

    # DEMO-ONLY: soft mode illustrates a stated limit with no real enforcement.
    # It must never be the default or be used as a production security control.
    enforcement_mode = os.getenv("ENFORCEMENT_MODE", "hard").lower()
    if enforcement_mode == "soft":
        if not allowed_by_scope:
            logger.warning(
                "SOFT MODE would have blocked requested amount ₹%s above "
                "authorized limit ₹%s",
                requested_amount,
                max_spend,
            )
        return ScopeCheckResult(
            allowed=True,
            reason="Allowed because DEMO-ONLY soft enforcement mode is enabled",
        )

    if not allowed_by_scope:
        return ScopeCheckResult(
            allowed=False,
            reason=(
                f"Requested ₹{requested_amount:g} exceeds authorized limit "
                f"of ₹{max_spend:g}"
            ),
        )

    return ScopeCheckResult(
        allowed=True,
        reason=f"Requested amount is within authorized limit of ₹{max_spend:g}",
    )
