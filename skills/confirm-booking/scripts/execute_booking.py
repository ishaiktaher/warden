"""Submit a constrained booking request to the local Warden proxy."""

import argparse
import json
import math
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_PROXY_URL = "http://127.0.0.1:8000"
PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from audit import record_audit_event


def _finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise argparse.ArgumentTypeError("value must be finite")
    return number


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute a booking through the scope-enforced Warden proxy."
    )
    parser.add_argument("--amount", required=True, type=_finite_number)
    parser.add_argument("--max-spend", required=True, type=_finite_number)
    parser.add_argument("--capability-token", required=True)
    parser.add_argument(
        "--resource",
        default="http://127.0.0.1:8080/",
        choices=("http://127.0.0.1:8080/",),
    )
    args = parser.parse_args()
    if args.amount <= 0:
        parser.error("--amount must be greater than zero")
    if args.max_spend < 0:
        parser.error("--max-spend must be non-negative")
    return args


def main() -> None:
    args = _parse_args()
    proxy_url = os.getenv("WARDEN_PROXY_URL", DEFAULT_PROXY_URL).rstrip("/")
    payload = {
        "amount": args.amount,
        "scope": {
            "action": "confirm_booking",
            "max_spend": args.max_spend,
        },
        "secret_ref": "dodo_payment_method",
        "capability_token": args.capability_token,
        "resource": args.resource,
    }
    record_audit_event(
        "booking_agent",
        "booking_requested",
        {"status": "started", "amount": args.amount, "max_spend": args.max_spend},
    )
    request = Request(
        f"{proxy_url}/bookings/execute",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=35) as response:
            result = json.load(response)
    except HTTPError as exc:
        record_audit_event("booking_agent", "operation_failed", {"status": "error"})
        print(json.dumps({"status": "error", "reason": f"Warden HTTP {exc.code}"}))
        raise SystemExit(1) from None
    except (URLError, TimeoutError):
        record_audit_event("booking_agent", "operation_failed", {"status": "error"})
        print(json.dumps({"status": "error", "reason": "Warden proxy unavailable"}))
        raise SystemExit(1) from None

    safe_status = result.get("status") if result.get("status") in {"success", "blocked"} else "error"
    record_audit_event(
        "booking_agent",
        "booking_completed",
        {"status": safe_status, "amount": args.amount},
    )
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
