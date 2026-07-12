"""Demonstrate real hard enforcement against an injected over-limit request."""

import json
import os

from proxy import execute_booking
from identity import issue_capability

AMOUNT = 6000
SCOPE = {"action": "confirm_booking", "max_spend": 5000}
SECRET_REF = "dodo_payment_method"
RESOURCE = "http://127.0.0.1:8080/"


def main() -> None:
    os.environ["ENFORCEMENT_MODE"] = "hard"
    token = issue_capability("booking", "confirm_booking", 5000, "INR", RESOURCE, 300)
    result = execute_booking(AMOUNT, SCOPE, SECRET_REF, token, RESOURCE)
    if result.get("status") != "blocked":
        raise RuntimeError("Hard-enforcement demo did not block the request")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
