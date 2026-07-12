"""Live Supabase/vault proof of single-use and expiring capabilities.

The Dodo boundary is replaced with a counting stub so this proof can verify
that replay never produces a second provider call without creating payments.
"""

import time
from unittest.mock import patch

from proxy.executor import execute_booking
from proxy.main import _issue_and_delegate_capability


RESOURCE = "http://127.0.0.1:8080/"
SCOPE = {"action": "confirm_booking", "max_spend": 5000}
SECRET_REF = "dodo_payment_method"


def _outcome(label: str, passed: bool, detail: str) -> bool:
    print(f"{'PASS' if passed else 'FAIL'} — {label}: {detail}")
    return passed


def main() -> None:
    all_passed = True
    with patch(
        "proxy.executor._charge_dodo_subscription",
        return_value="pay_capability_proof",
    ) as dodo_call:
        token, _ = _issue_and_delegate_capability(5000, 300)
        first = execute_booking(1000, SCOPE, SECRET_REF, token, RESOURCE)
        all_passed &= _outcome(
            "first presentation",
            first.get("status") == "success" and dodo_call.call_count == 1,
            f"status={first.get('status')}, reason={first.get('reason')}, "
            f"Dodo calls={dodo_call.call_count}",
        )

        replay = execute_booking(1000, SCOPE, SECRET_REF, token, RESOURCE)
        all_passed &= _outcome(
            "same token replay",
            replay.get("status") == "blocked"
            and "already consumed" in replay.get("reason", "").lower()
            and dodo_call.call_count == 1,
            f"status={replay.get('status')}, reason={replay.get('reason')}, "
            f"Dodo calls={dodo_call.call_count}",
        )

        expiring, _ = _issue_and_delegate_capability(5000, 1)
        time.sleep(2)
        expired = execute_booking(1000, SCOPE, SECRET_REF, expiring, RESOURCE)
        all_passed &= _outcome(
            "expired token",
            expired.get("status") == "blocked"
            and "expired" in expired.get("reason", "").lower()
            and dodo_call.call_count == 1,
            f"status={expired.get('status')}, reason={expired.get('reason')}, "
            f"Dodo calls={dodo_call.call_count}",
        )

    print("Dodo boundary was counted but stubbed; no payment was created by this proof.")
    raise SystemExit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
