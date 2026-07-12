"""Store the active Dodo test subscription ID in the encrypted vault."""

import os
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

from vault import store_secret

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_API_HOST = "test.dodopayments.com"
SECRET_REF = "dodo_payment_method"


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _test_base_url() -> str:
    parsed = urlparse(_required_env("DODO_API_BASE_URL"))
    if parsed.scheme != "https" or parsed.hostname != TEST_API_HOST:
        raise RuntimeError(
            "Refusing to run: DODO_API_BASE_URL must use Dodo test mode"
        )
    return f"https://{TEST_API_HOST}"


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    base_url = _test_base_url()
    response = requests.get(
        f"{base_url}/subscriptions",
        headers={"Authorization": f"Bearer {_required_env('DODO_API_KEY')}"},
        params={
            "customer_id": _required_env("DODO_CUSTOMER_ID"),
            "page_size": 100,
            "page_number": 0,
        },
        timeout=30,
    )
    response.raise_for_status()

    subscriptions = [
        item
        for item in response.json().get("items", [])
        if item.get("status") == "active" and item.get("on_demand") is True
    ]
    if len(subscriptions) != 1:
        raise RuntimeError(
            "Expected exactly one active on-demand subscription for the "
            f"configured customer; found {len(subscriptions)}"
        )

    subscription_id = subscriptions[0].get("subscription_id")
    if not subscription_id:
        raise RuntimeError("Dodo subscription response did not include subscription_id")

    store_secret(SECRET_REF, subscription_id)
    print("Stored active Dodo subscription in vault as dodo_payment_method")


if __name__ == "__main__":
    main()
