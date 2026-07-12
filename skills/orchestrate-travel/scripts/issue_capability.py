#!/usr/bin/env python3
"""Request a short-lived booking capability from the local Warden proxy."""

import argparse
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-spend", type=float, required=True)
    parser.add_argument("--proxy-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    request = Request(
        f"{args.proxy_url.rstrip('/')}/capabilities/issue",
        data=json.dumps({"max_spend": args.max_spend}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            print(json.dumps(json.load(response)))
    except HTTPError as exc:
        print(json.dumps({"status": "error", "reason": f"Warden HTTP {exc.code}"}))
        raise SystemExit(1) from None
    except (URLError, TimeoutError):
        print(json.dumps({"status": "error", "reason": "Warden proxy unavailable"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
