#!/usr/bin/env python3
"""Read-only Linkup client for the Hermes discovery specialist."""

import argparse
import json
from pathlib import Path
import sys

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integrations.linkup import LinkupDiscoveryError, search_flights
from audit import record_audit_event


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", required=True)
    args = parser.parse_args()
    load_dotenv(PROJECT_ROOT / ".env")
    record_audit_event("discovery_agent", "discovery_requested", {"status": "started"})

    try:
        result = search_flights(args.query)
    except (LinkupDiscoveryError, ValueError) as exc:
        record_audit_event("discovery_agent", "operation_failed", {"status": "error"})
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1

    record_audit_event(
        "discovery_agent",
        "discovery_completed",
        {
            "status": "success",
            "result_count": len(result["results"]),
            "trust": result["trust"],
        },
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
