import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from proxy.create_dodo_subscription import main


class CreateDodoSubscriptionTests(unittest.TestCase):
    @patch("proxy.create_dodo_subscription.requests.post")
    def test_creates_hosted_on_demand_authorization(self, post) -> None:
        response = Mock()
        response.json.return_value = {
            "checkout_url": "https://test.checkout.dodopayments.com/demo",
            "session_id": "cks_demo",
        }
        post.return_value = response

        output = io.StringIO()
        with patch.dict(
            os.environ,
            {
                "DODO_API_KEY": "test_key",
                "DODO_API_BASE_URL": "https://test.dodopayments.com",
                "DODO_CUSTOMER_ID": "cus_demo",
                "DODO_SUBSCRIPTION_PRODUCT_ID": "pdt_subscription_demo",
            },
        ):
            with redirect_stdout(output):
                main()

        request = post.call_args
        self.assertEqual(
            request.args[0],
            "https://test.dodopayments.com/checkouts",
        )
        self.assertEqual(request.kwargs["json"]["customer"], {"customer_id": "cus_demo"})
        self.assertEqual(
            request.kwargs["json"]["product_cart"],
            [{"product_id": "pdt_subscription_demo", "quantity": 1}],
        )
        self.assertEqual(
            request.kwargs["json"]["subscription_data"],
            {"on_demand": {"mandate_only": True}},
        )
        self.assertNotIn("payment_link", request.kwargs["json"])
        self.assertNotIn("payment_method_id", request.kwargs["json"])
        self.assertIn(
            "https://test.checkout.dodopayments.com/demo",
            output.getvalue(),
        )
        self.assertIn("DODO_CHECKOUT_SESSION_ID=cks_demo", output.getvalue())
        response.raise_for_status.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
