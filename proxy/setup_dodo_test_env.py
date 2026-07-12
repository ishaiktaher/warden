"""Create Dodo test-mode resources needed by the Warden checkout demo.

This script prints configuration for review; it never edits .env.
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


def _validated_test_base_url(raw_base_url: str) -> str:
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


def _confirm_test_api_key(
    session: requests.Session,
    base_url: str,
    headers: dict[str, str],
) -> None:
    """Confirm the key is accepted by the test host before creating resources."""
    response = session.get(
        f"{base_url}/customers",
        headers=headers,
        params={"page_size": 1, "page_number": 0},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if response.status_code in (401, 403):
        raise RuntimeError(
            "Refusing to run: DODO_API_KEY was not accepted by the test-mode API"
        )
    response.raise_for_status()


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")
    api_key = _required_env("DODO_API_KEY")
    base_url = _validated_test_base_url(_required_env("DODO_API_BASE_URL"))
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    with requests.Session() as session:
        _confirm_test_api_key(session, base_url, headers)

        customer_response = session.post(
            f"{base_url}/customers",
            headers=headers,
            json={
                "name": "Warden Demo Customer",
                "email": "warden-demo@example.com",
                "metadata": {"created_by": "warden_test_setup"},
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        customer_response.raise_for_status()
        customer_id = customer_response.json()["customer_id"]

        product_response = session.post(
            f"{base_url}/products",
            headers=headers,
            json={
                "name": "Warden Demo Flight Booking",
                "description": "Test-mode variable-price booking for Warden demos",
                "price": {
                    "currency": "INR",
                    # Dodo expects the minimum price in the smallest unit: ₹1.
                    "price": 100,
                    "type": "one_time_price",
                    "pay_what_you_want": True,
                    "suggested_price": 100_000,
                    "discount": 0,
                    "purchasing_power_parity": False,
                    "tax_inclusive": True,
                },
                # Dodo's API currently exposes no travel tax category; this is
                # the closest sensible placeholder for a test-only demo product.
                "tax_category": "digital_products",
                "metadata": {"created_by": "warden_test_setup"},
            },
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        product_response.raise_for_status()
        product_id = product_response.json()["product_id"]

    print("Dodo test resources created. Review and paste these into .env:")
    print(f"DODO_CUSTOMER_ID={customer_id}")
    print(f"DODO_PRODUCT_ID={product_id}")


if __name__ == "__main__":
    main()
