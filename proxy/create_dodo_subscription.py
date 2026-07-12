"""Create a Dodo Checkout Session for a test-mode on-demand mandate.

Card details must be entered only on Dodo's hosted checkout page; this script
never accepts or submits them.
"""

import os
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_API_HOST = "test.dodopayments.com"
REQUEST_TIMEOUT_SECONDS = 30


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _test_base_url() -> str:
    raw_base_url = _required_env("DODO_API_BASE_URL")
    parsed = urlparse(raw_base_url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != TEST_API_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path.rstrip("/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "Refusing to run: DODO_API_BASE_URL must be exactly "
            "https://test.dodopayments.com (an optional trailing slash is okay)"
        )
    return f"https://{TEST_API_HOST}"


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    api_key = _required_env("DODO_API_KEY")
    customer_id = _required_env("DODO_CUSTOMER_ID")
    product_id = _required_env("DODO_SUBSCRIPTION_PRODUCT_ID")
    base_url = _test_base_url()

    response = requests.post(
        f"{base_url}/checkouts",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "product_cart": [{"product_id": product_id, "quantity": 1}],
            "customer": {"customer_id": customer_id},
            # The current on-demand Checkout Sessions guide includes a full
            # billing address. These are harmless test-only placeholders.
            "billing_address": {
                "country": "IN",
                "city": "Bengaluru",
                "state": "Karnataka",
                "street": "1 Warden Demo Road",
                "zipcode": "560001",
            },
            "subscription_data": {"on_demand": {"mandate_only": True}},
            "return_url": "https://example.com/warden-demo-complete",
            "metadata": {"created_by": "warden_subscription_setup"},
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    body = response.json()

    checkout_url = body.get("checkout_url")
    if not checkout_url:
        raise RuntimeError("Dodo did not return checkout_url")

    print(
        "Open this link and complete checkout with a Dodo test card to "
        f"authorize the subscription: {checkout_url}"
    )

    session_id = body.get("session_id")
    if session_id:
        print(f"DODO_CHECKOUT_SESSION_ID={session_id}")
    print(
        "Checkout Sessions do not return subscription_id up front. After "
        "authorization, fetch it via GET /subscriptions."
    )


if __name__ == "__main__":
    main()
