"""ElevenLabs output adapter for sanitized Warden booking outcomes.

This module is deliberately a one-way communication boundary.  It accepts a
structured proxy result, creates a fixed message from an allowlist of statuses,
and sends only that message to ElevenLabs.  Raw agent text, provider errors and
payment identifiers must never cross this boundary.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any, Mapping, Protocol

import requests


ELEVENLABS_API_BASE_URL = "https://api.elevenlabs.io/v1"
DEFAULT_MODEL_ID = "eleven_multilingual_v2"
DEFAULT_OUTPUT_FORMAT = "mp3_44100_128"
_VOICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class ElevenLabsCommunicationError(RuntimeError):
    """A deliberately generic error that cannot expose provider details."""


class _HttpClient(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any: ...


def _safe_amount(value: Any) -> str | None:
    """Return a display-only rupee amount, or None for untrusted values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    amount = float(value)
    if not math.isfinite(amount) or amount < 0:
        return None
    return f"{amount:,.2f}".rstrip("0").rstrip(".")


def sanitize_booking_result(result: Mapping[str, Any]) -> str:
    """Create speech from approved fields without echoing arbitrary content.

    In particular, ``reason``, ``charge_id`` and every unknown field are
    intentionally ignored.  This prevents prompt injection, provider errors,
    secret references and payment identifiers from reaching the voice service.
    """
    status = result.get("status")
    amount = _safe_amount(result.get("amount"))

    if status == "success":
        if amount is None:
            return "Your booking was confirmed successfully."
        return f"Your booking was confirmed for {amount} rupees."

    if status == "blocked":
        return (
            "The booking was blocked because it exceeded the authorized "
            "spending limit. No charge was made."
        )

    # Do not relay raw API failures or arbitrary agent-generated explanations.
    return "The booking could not be completed. No further details are available."


def build_safe_announcement(result: Mapping[str, Any]) -> str:
    """Public communication-agent contract for a sanitized announcement."""
    return sanitize_booking_result(result)


def text_to_speech_for_booking(
    result: Mapping[str, Any],
    *,
    http_client: _HttpClient = requests,
    timeout: float = 15.0,
) -> bytes:
    """Generate MP3 speech for a sanitized booking result using ElevenLabs."""
    api_key = os.getenv("ELEVENLABS_API_KEY", "").strip()
    voice_id = os.getenv("ELEVENLABS_VOICE_ID", "").strip()
    if not api_key:
        raise ElevenLabsCommunicationError("ElevenLabs communication is not configured.")
    if not voice_id or not _VOICE_ID_PATTERN.fullmatch(voice_id):
        raise ElevenLabsCommunicationError("ElevenLabs communication is not configured.")

    message = sanitize_booking_result(result)
    url = f"{ELEVENLABS_API_BASE_URL}/text-to-speech/{voice_id}"

    try:
        response = http_client.post(
            url,
            headers={"xi-api-key": api_key, "Content-Type": "application/json"},
            params={"output_format": DEFAULT_OUTPUT_FORMAT},
            json={"text": message, "model_id": DEFAULT_MODEL_ID},
            timeout=timeout,
        )
        response.raise_for_status()
        audio = bytes(response.content)
    except (requests.RequestException, TypeError, ValueError, AttributeError) as exc:
        # Never include the upstream response, request or secret in this error.
        raise ElevenLabsCommunicationError(
            "Voice announcement could not be generated."
        ) from exc

    if not audio:
        raise ElevenLabsCommunicationError("Voice announcement could not be generated.")
    return audio


def synthesize_booking_announcement(
    result: Mapping[str, Any],
    *,
    http_client: _HttpClient = requests,
    timeout: float = 15.0,
) -> bytes:
    """Public communication-agent contract returning MP3 bytes."""
    return text_to_speech_for_booking(
        result,
        http_client=http_client,
        timeout=timeout,
    )
