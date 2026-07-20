"""Command-line interface for Warden operators and agent developers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from .client import WardenClient, WardenError


def _client() -> WardenClient:
    return WardenClient(
        os.getenv("WARDEN_URL", "http://127.0.0.1:8000"),
        access_token=os.getenv("WARDEN_ACCESS_TOKEN"),
        admin_key=os.getenv("WARDEN_ADMIN_KEY"),
    )


def _document(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON input must be an object")
    return value


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="warden", description="Warden agent authorization CLI"
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("health", help="Check the configured Warden service")
    integrations = commands.add_parser(
        "integrations", help="Search integration coverage"
    )
    integrations.add_argument("--kind", choices=["oauth2", "managed_secret"])
    integrations.add_argument("--query")
    commands.add_parser("agents", help="List registered agents (administrator)")
    commands.add_parser("audit-verify", help="Verify the audit hash chain")
    execute = commands.add_parser(
        "execute", help="Execute an ActionRequest JSON document"
    )
    execute.add_argument(
        "--file", required=True, help="Path to an ActionRequest JSON file"
    )
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        client = _client()
        result: Any
        if args.command == "health":
            result = client.health()
        elif args.command == "integrations":
            result = client.integrations(kind=args.kind, query=args.query)
        elif args.command == "agents":
            result = client.agents()
        elif args.command == "audit-verify":
            result = client.audit_verify()
        elif args.command == "execute":
            result = client.execute(**_document(args.file))
        else:
            raise ValueError("Unknown command")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (WardenError, ValueError, OSError) as exc:
        print(f"warden: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
