#!/usr/bin/env python3
"""ElevenLabs client that accepts only a sanitized booking result shape."""

import argparse
from pathlib import Path
import sys

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integrations.elevenlabs import (
    ElevenLabsCommunicationError,
    synthesize_booking_announcement,
)
from audit import record_audit_event


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", choices=("success", "blocked"), required=True)
    parser.add_argument("--amount", type=float, required=True)
    # Accepted for a stable agent contract, but the voice boundary intentionally
    # ignores raw reasons so injected text can never be sent to ElevenLabs.
    parser.add_argument("--reason", default="")
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "demo" / "warden-booking-result.mp3",
    )
    args = parser.parse_args()
    load_dotenv(PROJECT_ROOT / ".env")
    record_audit_event(
        "communication_agent",
        "announcement_requested",
        {"status": "started", "amount": args.amount},
    )

    try:
        audio = synthesize_booking_announcement(
            {"status": args.status, "amount": args.amount, "reason": args.reason}
        )
    except ElevenLabsCommunicationError as exc:
        record_audit_event("communication_agent", "operation_failed", {"status": "error"})
        print(str(exc), file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(audio)
    record_audit_event(
        "communication_agent",
        "announcement_completed",
        {"status": "success", "amount": args.amount},
    )
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
