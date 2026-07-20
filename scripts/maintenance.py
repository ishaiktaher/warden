"""Scheduled production maintenance: reconcile claims and anchor audit history."""

from __future__ import annotations

import argparse
import json

from control_plane.service import ControlPlane


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("reconcile", "anchor"))
    parser.add_argument("--stale-after-seconds", type=int, default=300)
    args = parser.parse_args()
    plane = ControlPlane()
    if args.operation == "reconcile":
        result = plane.reconcile_stale_operations(
            "scheduled-maintenance", args.stale_after_seconds
        )
    else:
        result = plane.audit.anchor("scheduled-maintenance")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
