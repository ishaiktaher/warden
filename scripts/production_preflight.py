"""Validate production configuration without printing any secret values."""

from __future__ import annotations

import argparse
import json

from control_plane.config import load_settings
from control_plane.preflight import evaluate_production_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Warden production configuration without printing secrets."
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat operational warnings as deployment blockers.",
    )
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except (RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)], "warnings": []}, indent=2))
        return 1
    result = evaluate_production_settings(settings)
    body = result.as_dict()
    if args.strict and result.warnings:
        body["status"] = "blocked"
        body["errors"] = [
            "Strict production preflight requires all operational warnings to be resolved"
        ]
    print(json.dumps(body, indent=2))
    return 0 if result.ok and (not args.strict or not result.warnings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
