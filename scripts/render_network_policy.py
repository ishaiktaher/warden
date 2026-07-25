"""Render the environment-specific Warden egress NetworkPolicy as JSON."""

from __future__ import annotations

import argparse
import ipaddress
import json


def _cidrs(value: str, label: str) -> list[str]:
    result: list[str] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise SystemExit(f"{label} contains an invalid CIDR") from exc
        if network.prefixlen == 0:
            raise SystemExit(f"{label} cannot allow the entire internet")
        result.append(str(network))
    if not result:
        raise SystemExit(f"{label} must contain at least one CIDR")
    return result


def _rule(cidrs: list[str], port: int) -> dict:
    return {
        "to": [{"ipBlock": {"cidr": cidr}} for cidr in cidrs],
        "ports": [{"protocol": "TCP", "port": port}],
    }


def render(postgres: str, redis: str, https: str) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "warden-approved-egress", "namespace": "warden"},
        "spec": {
            "podSelector": {"matchLabels": {"app": "warden-control-plane"}},
            "policyTypes": ["Egress"],
            "egress": [
                _rule(_cidrs(postgres, "PostgreSQL egress"), 5432),
                _rule(_cidrs(redis, "Redis egress"), 6379),
                _rule(_cidrs(https, "HTTPS egress"), 443),
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--postgres", required=True)
    parser.add_argument("--redis", required=True)
    parser.add_argument("--https", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(render(args.postgres, args.redis, args.https), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
