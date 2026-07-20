"""Generate deterministic public proof metadata from executable repository state."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import unittest

from control_plane.integrations import catalog_summary


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "ui" / "proof.json"


def _count(suite: unittest.TestSuite) -> int:
    return sum(
        _count(item) if isinstance(item, unittest.TestSuite) else 1
        for item in suite
    )


def proof() -> dict:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    integrations = catalog_summary()
    return {
        "schema_version": 1,
        "test_cases": _count(suite),
        "catalog_entries": integrations["total"],
        "contract_tested_integrations": integrations["contract_tested"],
        "live_verified_integrations": integrations["live_verified"],
        "source": "repository-test-discovery",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(proof(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != rendered:
            print("ui/proof.json is stale; run python -m scripts.generate_proof", file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
