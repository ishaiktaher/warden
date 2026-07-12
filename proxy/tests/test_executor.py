import os
import unittest
from unittest.mock import Mock, patch

from enforcer import ScopeCheckResult
from identity.capability import VerifyResult
from proxy.executor import (
    DodoPaymentError,
    _charge_dodo_subscription,
    _safe_dodo_error,
    execute_booking,
    execute_booking_without_warden_demo,
)


class ExecuteBookingTests(unittest.TestCase):
    def test_safe_dodo_error_exposes_code_but_not_raw_message(self) -> None:
        response = Mock(status_code=409)
        response.json.return_value = {
            "code": "PREVIOUS_PAYMENT_PENDING",
            "message": "secret-bearing upstream text",
        }
        message = _safe_dodo_error(response)
        self.assertEqual(
            message, "Dodo charge conflict: the previous payment is still pending"
        )
        self.assertNotIn("secret-bearing", message)
    @patch("proxy.executor._charge_dodo_subscription", return_value="pay_demo")
    @patch("proxy.executor.resolve_secret", return_value="sub_demo")
    def test_unsafe_demo_requires_test_host_and_explicit_enable(self, resolve, charge) -> None:
        with patch.dict(os.environ, {"ALLOW_UNSAFE_DEMO": "false", "DODO_API_BASE_URL": "https://test.dodopayments.com"}):
            with self.assertRaisesRegex(DodoPaymentError, "disabled"):
                execute_booking_without_warden_demo(6000, "dodo_payment_method")
        resolve.assert_not_called()
        charge.assert_not_called()

    @patch("proxy.executor._charge_dodo_subscription", return_value="pay_demo")
    @patch("proxy.executor.resolve_secret", return_value="sub_demo")
    def test_unsafe_demo_bypasses_scope_only_in_test_mode(self, resolve, charge) -> None:
        with patch.dict(os.environ, {"ALLOW_UNSAFE_DEMO": "true", "DODO_API_BASE_URL": "https://test.dodopayments.com"}):
            result = execute_booking_without_warden_demo(6000, "dodo_payment_method")
        self.assertEqual(result["gate"], "bypassed")
        resolve.assert_called_once_with("dodo_payment_method")
        charge.assert_called_once_with(6000, "sub_demo")
    @patch("proxy.executor.requests.post")
    def test_dodo_error_redacts_subscription_id(self, post) -> None:
        response = Mock(status_code=404)
        post.return_value = response
        response.raise_for_status.side_effect = __import__("requests").HTTPError(
            "404 for https://test.dodopayments.com/subscriptions/sub_secret/charge",
            response=response,
        )

        with patch.dict(
            os.environ,
            {
                "DODO_API_KEY": "test_key",
                "DODO_API_BASE_URL": "https://test.dodopayments.com",
            },
        ):
            with self.assertRaises(DodoPaymentError) as raised:
                _charge_dodo_subscription(100, "sub_secret")

        self.assertEqual(
            str(raised.exception),
            "Dodo subscription charge failed with HTTP 404",
        )
        self.assertNotIn("sub_secret", str(raised.exception))
    @patch("proxy.executor.requests.post")
    def test_subscription_charge_uses_documented_request_shape(self, post) -> None:
        response = Mock()
        response.json.return_value = {"payment_id": "pay_demo"}
        post.return_value = response

        with patch.dict(
            os.environ,
            {
                "DODO_API_KEY": "test_key",
                "DODO_API_BASE_URL": "https://test.dodopayments.com",
            },
        ):
            charge_id = _charge_dodo_subscription(123.45, "sub_demo")

        self.assertEqual(charge_id, "pay_demo")
        post.assert_called_once_with(
            "https://test.dodopayments.com/subscriptions/sub_demo/charge",
            headers={
                "Authorization": "Bearer test_key",
                "Content-Type": "application/json",
            },
            json={"product_price": 12345},
            timeout=30,
        )
        response.raise_for_status.assert_called_once_with()

    @patch("proxy.executor._charge_dodo_subscription")
    @patch("proxy.executor.resolve_secret")
    @patch("proxy.executor.check_scope")
    @patch("proxy.executor.capability_claims")
    @patch("proxy.executor.verify_capability")
    def test_blocked_request_never_resolves_or_charges(
        self,
        verify,
        claims,
        check_scope,
        resolve_secret,
        create_charge,
    ) -> None:
        verify.return_value = VerifyResult(True, "Capability verified", "grant")
        claims.return_value = {"action": "confirm_booking", "max_spend": 5000}
        check_scope.return_value = ScopeCheckResult(False, "over limit")

        result = execute_booking(
            6000, {"action": "confirm_booking"}, "ref", "token", "http://127.0.0.1:8080/"
        )

        self.assertEqual(
            result,
            {"status": "blocked", "reason": "over limit", "amount": 6000},
        )
        resolve_secret.assert_not_called()
        create_charge.assert_not_called()

    @patch("proxy.executor._charge_dodo_subscription", return_value="pay_demo")
    @patch("proxy.executor.resolve_secret", return_value="sub_demo")
    @patch("proxy.executor.check_scope")
    @patch("proxy.executor.capability_claims")
    @patch("proxy.executor.verify_capability")
    def test_allowed_request_resolves_then_charges(
        self,
        verify,
        claims,
        check_scope,
        resolve_secret,
        create_charge,
    ) -> None:
        verify.return_value = VerifyResult(True, "Capability verified", "grant")
        claims.return_value = {"action": "confirm_booking", "max_spend": 5000}
        check_scope.return_value = ScopeCheckResult(True, "within limit")
        scope = {"action": "confirm_booking", "max_spend": 999999}

        result = execute_booking(
            1000, scope, "dodo_payment_method", "token", "http://127.0.0.1:8080/"
        )

        self.assertEqual(
            result,
            {"status": "success", "charge_id": "pay_demo", "amount": 1000},
        )
        check_scope.assert_called_once_with(
            1000, {"action": "confirm_booking", "max_spend": 5000}
        )
        resolve_secret.assert_called_once_with("dodo_payment_method")
        create_charge.assert_called_once_with(1000, "sub_demo")

    @patch("proxy.executor._charge_dodo_subscription")
    @patch("proxy.executor.resolve_secret")
    @patch("proxy.executor.check_scope")
    @patch("proxy.executor.verify_capability")
    def test_rejected_capability_stops_before_scope_vault_and_dodo(
        self, verify, check_scope, resolve_secret, charge
    ) -> None:
        verify.return_value = VerifyResult(False, "Capability already consumed", "grant")
        result = execute_booking(
            1000,
            {"action": "confirm_booking", "max_spend": 5000},
            "dodo_payment_method",
            "replayed-token",
            "http://127.0.0.1:8080/",
        )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "Capability already consumed")
        check_scope.assert_not_called()
        resolve_secret.assert_not_called()
        charge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
