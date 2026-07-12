#!/usr/bin/env python3
"""Record an allowlisted orchestrator event in Warden's local audit trail."""

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from audit import record_audit_event


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", choices=("workflow_started", "delegation_requested"), required=True)
    parser.add_argument("--status", choices=("started", "success", "blocked", "error"), required=True)
    args = parser.parse_args()
    record_audit_event("travel_orchestrator", args.event, {"status": args.status})


if __name__ == "__main__":
    main()
