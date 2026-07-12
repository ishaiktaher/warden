"""Read-only, redacted Dodo subscription health check for the test demo."""

import os
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from vault import resolve_secret


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_HOST = "test.dodopayments.com"


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    base_url = os.getenv("DODO_API_BASE_URL", "").rstrip("/")
    if urlparse(base_url).hostname != TEST_HOST:
        raise RuntimeError("Refusing status check outside Dodo test mode")
    api_key = os.getenv("DODO_API_KEY")
    if not api_key:
        raise RuntimeError("DODO_API_KEY is not configured")

    # Secret resolution remains inside proxy code. The identifier is used only
    # in the request URL and is never printed, logged, or returned.
    subscription_id = resolve_secret("dodo_payment_method")
    response = requests.get(
        f"{base_url}/subscriptions/{subscription_id}",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    response.raise_for_status()
    body = response.json()
    print(f"status={body.get('status', 'unknown')}")
    print(f"on_demand={body.get('on_demand', 'unknown')}")
    print(f"currency={body.get('currency', body.get('billing_currency', 'unknown'))}")
    payments = requests.get(
        f"{base_url}/payments",
        headers={"Authorization": f"Bearer {api_key}"},
        params={"subscription_id": subscription_id, "page_size": 10, "page_number": 0},
        timeout=30,
    )
    payments.raise_for_status()
    safe_payments = [
        {
            "status": item.get("status", "unknown"),
            "total_amount": item.get("total_amount", "unknown"),
            "currency": item.get("currency", "unknown"),
            "created_at": item.get("created_at", "unknown"),
        }
        for item in payments.json().get("items", [])
    ]
    print(f"recent_payments={safe_payments}")
    print("Subscription ID intentionally redacted.")


if __name__ == "__main__":
    main()
