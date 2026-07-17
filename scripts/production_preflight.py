"""Validate production configuration without printing any secret values."""

from __future__ import annotations

import json

from control_plane.config import load_settings
from control_plane.preflight import evaluate_production_settings


def main() -> int:
    try:
        settings = load_settings()
    except (RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "errors": [str(exc)], "warnings": []}, indent=2))
        return 1
    result = evaluate_production_settings(settings)
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
