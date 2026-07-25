"""Production egress policy rendering tests."""

from __future__ import annotations

import unittest

from scripts.render_network_policy import render


class RenderNetworkPolicyTests(unittest.TestCase):
    def test_ports_are_scoped_to_reviewed_destination_cidrs(self) -> None:
        policy = render(
            "10.10.0.5/32",
            "10.20.0.0/24",
            "10.30.0.8/32,2001:db8::8/128",
        )
        rules = policy["spec"]["egress"]
        self.assertEqual([5432, 6379, 443], [rule["ports"][0]["port"] for rule in rules])
        self.assertEqual(
            [{"ipBlock": {"cidr": "10.10.0.5/32"}}],
            rules[0]["to"],
        )

    def test_entire_internet_and_invalid_values_are_rejected(self) -> None:
        for value in ("0.0.0.0/0", "::/0", "not-a-cidr"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                render(value, "10.20.0.1/32", "10.30.0.1/32")


if __name__ == "__main__":
    unittest.main()
