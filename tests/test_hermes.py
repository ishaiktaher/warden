import subprocess
import unittest
from unittest.mock import Mock, patch

from integrations.hermes import FLIGHT_BOOKING, OTHER, HermesRoutingError, classify_intent


class HermesIntentRouterTests(unittest.TestCase):
    @patch("integrations.hermes.shutil.which", return_value="/test/hermes")
    def test_accepts_only_exact_flight_booking_decision(self, _which) -> None:
        runner = Mock(return_value=subprocess.CompletedProcess([], 0, "FLIGHT_BOOKING\n", ""))
        self.assertEqual(classify_intent("Book a flight", runner=runner), FLIGHT_BOOKING)
        prompt = runner.call_args.args[0][2]
        self.assertIn("<USER_TEXT>\nBook a flight\n</USER_TEXT>", prompt)

    @patch("integrations.hermes.shutil.which", return_value="/test/hermes")
    def test_fails_closed_on_verbose_or_other_output(self, _which) -> None:
        for output in ("OTHER", "I think FLIGHT_BOOKING", "", "flight booking"):
            runner = Mock(return_value=subprocess.CompletedProcess([], 0, output, ""))
            with self.subTest(output=output):
                self.assertEqual(classify_intent("hello", runner=runner), OTHER)

    @patch("integrations.hermes.shutil.which", return_value=None)
    def test_missing_hermes_fails_closed(self, _which) -> None:
        with self.assertRaises(HermesRoutingError):
            classify_intent("Book a flight")


if __name__ == "__main__":
    unittest.main()
