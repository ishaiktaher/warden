import tempfile
from pathlib import Path
import unittest

from proxy.demo_request import infer_authorized_maximum, read_demo_flight_price


class DemoRequestTests(unittest.TestCase):
    def test_infers_authorization_from_natural_instruction(self) -> None:
        self.assertEqual(
            infer_authorized_maximum("Book it. I authorize a maximum spend of ₹5,000."),
            5000,
        )

    def test_rejects_instruction_without_explicit_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit maximum"):
            infer_authorized_maximum("Book the flight")

    def test_handles_common_wispr_transcriptions(self) -> None:
        examples = {
            "Book it with a budget of INR 5,000": 5000,
            "Book it, up to 5000 rupees": 5000,
            "Book it; 5,000 rupees maximum": 5000,
            "I authorize up to five thousand rupees": 5000,
            "My spending limit is five thousand": 5000,
        }
        for text, expected in examples.items():
            with self.subTest(text=text):
                self.assertEqual(infer_authorized_maximum(text), expected)

    def test_reads_structured_price_from_demo_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            page = Path(directory) / "index.html"
            page.write_text('<article data-flight-price-inr="6000">', encoding="utf-8")
            self.assertEqual(read_demo_flight_price(page), 6000)


if __name__ == "__main__":
    unittest.main()
