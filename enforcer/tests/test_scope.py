import os
import unittest
from unittest.mock import patch

from enforcer import check_scope


class CheckScopeTests(unittest.TestCase):
    def test_under_limit_is_allowed(self) -> None:
        with patch.dict(os.environ, {"ENFORCEMENT_MODE": "hard"}):
            result = check_scope(75.0, {"action": "pay", "max_spend": 100.0})

        self.assertTrue(result.allowed)

    def test_over_limit_is_blocked(self) -> None:
        with patch.dict(os.environ, {"ENFORCEMENT_MODE": "hard"}):
            result = check_scope(125.0, {"action": "pay", "max_spend": 100.0})

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "Requested ₹125 exceeds authorized limit of ₹100",
        )

    def test_exactly_at_limit_is_allowed(self) -> None:
        with patch.dict(os.environ, {"ENFORCEMENT_MODE": "hard"}):
            result = check_scope(100.0, {"action": "pay", "max_spend": 100.0})

        self.assertTrue(result.allowed)

    def test_soft_mode_always_passes(self) -> None:
        with patch.dict(os.environ, {"ENFORCEMENT_MODE": "soft"}):
            with self.assertLogs("enforcer.scope", level="WARNING") as logs:
                result = check_scope(
                    1_000.0,
                    {"action": "pay", "max_spend": 100.0},
                )

        self.assertTrue(result.allowed)
        self.assertIn("would have blocked", logs.output[0])


if __name__ == "__main__":
    unittest.main()
