#!/usr/bin/env python3
"""Run the architecture document's support-ticket example locally."""

import json

from control_plane import ControlPlane


def main() -> None:
    result = ControlPlane().run_support_ticket_scenario(
        principal_id="customer-success-user", admin_actor="control-plane-admin"
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
