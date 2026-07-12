"""Create the recurring Dodo test product used for on-demand mandates."""

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
    parsed = urlparse(_required_env("DODO_API_BASE_URL"))
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
    base_url = _test_base_url()

    response = requests.post(
        f"{base_url}/products",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "name": "Warden Demo On-Demand Booking Authorization",
            "description": "Test recurring product for Warden mandate authorization",
            "price": {
                "currency": "INR",
                "discount": 0,
                "payment_frequency_count": 1,
                "payment_frequency_interval": "Month",
                # Required recurring base price in paise. The later on-demand
                # charge supplies its own product_price; mandate_only prevents
                # this base price from being charged during authorization.
                "price": 100,
                "purchasing_power_parity": False,
                "subscription_period_count": 12,
                "subscription_period_interval": "Month",
                "type": "recurring_price",
                "tax_inclusive": True,
                "trial_period_days": 0,
            },
            # Dodo's product API currently exposes only digital categories;
            # `saas` is the closest test-only category for the Warden service.
            "tax_category": "saas",
            "metadata": {"created_by": "warden_subscription_product_setup"},
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    product_id = response.json().get("product_id")
    if not product_id:
        raise RuntimeError("Dodo product response did not include product_id")

    print(f"DODO_SUBSCRIPTION_PRODUCT_ID={product_id}")


if __name__ == "__main__":
    main()
