"""DEMO ONLY: show how a stated but unenforced limit can be bypassed."""

import argparse
import json
import os
from pathlib import Path

from dotenv import load_dotenv

from proxy import execute_booking
from identity import issue_capability

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AMOUNT = 6000
SCOPE = {"action": "confirm_booking", "max_spend": 5000}
SECRET_REF = "dodo_payment_method"
TEST_API_BASE_URL = "https://test.dodopayments.com"
RESOURCE = "http://127.0.0.1:8080/"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DEMO ONLY: execute an over-limit Dodo test charge in soft mode."
    )
    parser.add_argument(
        "--confirm-test-charge",
        action="store_true",
        help="acknowledge that this creates a ₹6,000 Dodo test-mode charge",
    )
    args = parser.parse_args()
    if not args.confirm_test_charge:
        parser.error("--confirm-test-charge is required")

    load_dotenv(PROJECT_ROOT / ".env")
    if os.getenv("DODO_API_BASE_URL", "").rstrip("/") != TEST_API_BASE_URL:
        raise RuntimeError("Soft-mode demo refuses to run outside Dodo test mode")

    # DEMO ONLY. Never use soft mode as a production security control.
    os.environ["ENFORCEMENT_MODE"] = "soft"
    token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
    result = execute_booking(AMOUNT, SCOPE, SECRET_REF, token, RESOURCE)
    if result.get("status") != "success":
        raise RuntimeError("Soft-mode demo did not create the expected test charge")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
