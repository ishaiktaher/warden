"""Execute Dodo Payments actions after model-independent scope checks."""

import os
import re
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import requests
from dotenv import load_dotenv

from enforcer import check_scope
from vault import resolve_secret
from audit import record_audit_event
from identity.capability import capability_claims, verify_capability

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DODO_API_BASE_URL = "https://live.dodopayments.com"


class DodoPaymentError(RuntimeError):
    """A redacted Dodo failure safe to expose outside the proxy boundary."""


_DODO_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,80}$")


def _safe_dodo_error(response: requests.Response) -> str:
    code = None
    try:
        payload = response.json()
        candidate = payload.get("code") if isinstance(payload, dict) else None
        if isinstance(candidate, str) and _DODO_ERROR_CODE.fullmatch(candidate):
            code = candidate
    except (ValueError, AttributeError):
        pass

    status = response.status_code
    if code == "PREVIOUS_PAYMENT_PENDING":
        return "Dodo charge conflict: the previous payment is still pending"
    if code == "SUBSCRIPTION_PAYMENT_RETRY_LIMIT_EXCEEDED":
        return "Dodo charge conflict: subscription retry limit exceeded"
    if code == "SUBSCRIPTION_INACTIVE":
        return "Dodo charge conflict: subscription is not active"
    if code == "SUBSCRIPTION_EXPIRED":
        return "Dodo charge conflict: subscription has expired"
    if code:
        return f"Dodo subscription charge failed with HTTP {status} ({code})"
    return f"Dodo subscription charge failed with HTTP {status}"


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _amount_in_paise(amount: float) -> int:
    return int(
        (Decimal(str(amount)) * Decimal("100")).quantize(
            Decimal("1"),
            rounding=ROUND_HALF_UP,
        )
    )


def _charge_dodo_subscription(amount: float, subscription_id: str) -> str:
    load_dotenv(PROJECT_ROOT / ".env")
    api_key = _required_env("DODO_API_KEY")
    api_base_url = os.getenv("DODO_API_BASE_URL", DEFAULT_DODO_API_BASE_URL).rstrip("/")

    try:
        response = requests.post(
            f"{api_base_url}/subscriptions/{subscription_id}/charge",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={"product_price": _amount_in_paise(amount)},
            timeout=30,
        )
        response.raise_for_status()
        body = response.json()
    except requests.HTTPError as exc:
        if exc.response is None:
            raise DodoPaymentError(
                "Dodo subscription charge failed with HTTP unknown"
            ) from None
        raise DodoPaymentError(_safe_dodo_error(exc.response)) from None
    except requests.RequestException:
        raise DodoPaymentError("Dodo subscription charge request failed") from None

    charge_id = body.get("payment_id")
    if not charge_id:
        raise DodoPaymentError("Dodo subscription charge returned no payment ID")
    return charge_id


def execute_booking(
    amount: float,
    scope: dict,
    secret_ref: str,
    capability_token: str,
    resource: str,
) -> dict:
    """Verify capability, enforce its signed scope, then charge Dodo."""
    verification = verify_capability(
        capability_token,
        expected_agent_id="booking",
        expected_action="confirm_booking",
        expected_resource=resource,
    )
    if not verification.valid:
        # This identity gate MUST stay before check_scope, vault, and Dodo.
        return {
            "status": "blocked",
            "reason": verification.reason,
            "amount": amount,
        }

    claims = capability_claims(capability_token)
    signed_scope = {
        "action": claims["action"],
        "max_spend": claims["max_spend"],
    }
    scope_result = check_scope(amount, signed_scope)
    audit_metadata = {"allowed": scope_result.allowed, "amount": amount}
    audit_metadata["max_spend"] = signed_scope["max_spend"]
    record_audit_event("warden", "scope_checked", audit_metadata)
    if not scope_result.allowed:
        # This return must remain before secret resolution and all network calls.
        result = {
            "status": "blocked",
            "reason": scope_result.reason,
            "amount": amount,
        }
        record_audit_event(
            "warden", "booking_completed", {"status": "blocked", "amount": amount}
        )
        return result

    # The resolved subscription ID exists only inside proxy code and is never
    # logged or returned. Dodo holds the authorized payment method server-side.
    subscription_id = resolve_secret(secret_ref)
    try:
        charge_id = _charge_dodo_subscription(amount, subscription_id)
    except DodoPaymentError:
        record_audit_event("warden", "operation_failed", {"status": "error"})
        raise
    record_audit_event(
        "warden", "booking_completed", {"status": "success", "amount": amount}
    )
    return {"status": "success", "charge_id": charge_id, "amount": amount}


def execute_booking_without_warden_demo(amount: float, secret_ref: str) -> dict:
    """DEMO ONLY: charge without checking scope, restricted to Dodo test mode."""
    load_dotenv(PROJECT_ROOT / ".env")
    api_base_url = os.getenv("DODO_API_BASE_URL", DEFAULT_DODO_API_BASE_URL).rstrip("/")
    if os.getenv("ALLOW_UNSAFE_DEMO", "false").lower() != "true":
        raise DodoPaymentError("Unsafe comparison mode is disabled")
    if "test.dodopayments.com" not in api_base_url:
        raise DodoPaymentError("Unsafe comparison mode requires Dodo test mode")

    record_audit_event(
        "unsafe_demo_proxy", "scope_bypassed", {"status": "started", "amount": amount}
    )
    subscription_id = resolve_secret(secret_ref)
    try:
        charge_id = _charge_dodo_subscription(amount, subscription_id)
    except DodoPaymentError:
        record_audit_event(
            "unsafe_demo_proxy", "operation_failed", {"status": "error"}
        )
        raise
    record_audit_event(
        "unsafe_demo_proxy", "booking_completed", {"status": "success", "amount": amount}
    )
    return {"status": "success", "charge_id": charge_id, "amount": amount, "gate": "bypassed"}
