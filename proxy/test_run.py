"""Manually exercise one allowed and one blocked booking request.

WARNING: The first call creates a real Dodo charge when live credentials and a
real saved payment method are configured. Run this script intentionally.
"""

from proxy import execute_booking
from identity import issue_capability

SCOPE = {"action": "confirm_booking", "max_spend": 5000}
SECRET_REF = "dodo_payment_method"
RESOURCE = "http://127.0.0.1:8080/"


def main() -> None:
    below_token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
    below_limit = execute_booking(1000, SCOPE, SECRET_REF, below_token, RESOURCE)
    print(below_limit)

    above_token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
    above_limit = execute_booking(6000, SCOPE, SECRET_REF, above_token, RESOURCE)
    print(above_limit)


if __name__ == "__main__":
    main()
