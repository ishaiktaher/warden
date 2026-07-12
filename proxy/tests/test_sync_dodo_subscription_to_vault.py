import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from proxy.sync_dodo_subscription_to_vault import main


class SyncDodoSubscriptionToVaultTests(unittest.TestCase):
    @patch("proxy.sync_dodo_subscription_to_vault.store_secret")
    @patch("proxy.sync_dodo_subscription_to_vault.requests.get")
    def test_stores_only_active_on_demand_subscription(self, get, store_secret) -> None:
        response = Mock()
        response.json.return_value = {
            "items": [
                {
                    "subscription_id": "sub_demo",
                    "status": "active",
                    "on_demand": True,
                }
            ]
        }
        get.return_value = response

        output = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DODO_API_KEY": "test_key",
                "DODO_API_BASE_URL": "https://test.dodopayments.com",
                "DODO_CUSTOMER_ID": "cus_demo",
            },
        ):
            with redirect_stdout(output):
                main()

        store_secret.assert_called_once_with("dodo_payment_method", "sub_demo")
        self.assertNotIn("sub_demo", output.getvalue())
        response.raise_for_status.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
