import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from proxy.create_dodo_subscription_product import main


class CreateDodoSubscriptionProductTests(unittest.TestCase):
    @patch("proxy.create_dodo_subscription_product.requests.post")
    def test_creates_recurring_product_without_reusing_one_time_id(self, post) -> None:
        response = Mock()
        response.json.return_value = {"product_id": "pdt_recurring_demo"}
        post.return_value = response

        output = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DODO_API_KEY": "test_key",
                "DODO_API_BASE_URL": "https://test.dodopayments.com",
                "DODO_PRODUCT_ID": "pdt_existing_one_time",
            },
        ):
            with redirect_stdout(output):
                main()

        request = post.call_args
        self.assertEqual(
            request.args[0],
            "https://test.dodopayments.com/products",
        )
        price = request.kwargs["json"]["price"]
        self.assertEqual(price["type"], "recurring_price")
        self.assertEqual(price["payment_frequency_count"], 1)
        self.assertEqual(price["payment_frequency_interval"], "Month")
        self.assertEqual(price["subscription_period_count"], 12)
        self.assertEqual(price["subscription_period_interval"], "Month")
        self.assertNotIn("pay_what_you_want", price)
        self.assertIn(
            "DODO_SUBSCRIPTION_PRODUCT_ID=pdt_recurring_demo",
            output.getvalue(),
        )
        response.raise_for_status.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
