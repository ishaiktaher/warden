"""Read-only Linkup discovery whose output is always untrusted evidence.

This adapter deliberately knows nothing about authorization scopes, the vault,
or payments. A caller may present these results to an agent or user, but must
never interpret them as instructions or authority to perform an action.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Literal

import requests


DEFAULT_LINKUP_API_BASE_URL = "https://api.linkup.so"
TRUST_CLASSIFICATION = "untrusted_web_evidence"
PUBLIC_TRUST_MARKER = "untrusted_external_evidence"
_VALID_DEPTHS = frozenset({"fast", "standard", "deep"})


class LinkupDiscoveryError(RuntimeError):
    """Raised when read-only discovery cannot return valid evidence."""


@dataclass(frozen=True)
class UntrustedSearchResult:
    """A single web result; every string may contain hostile instructions."""

    name: str
    url: str
    content: str
    result_type: str


@dataclass(frozen=True)
class FlightDiscoveryEvidence:
    """Untrusted search evidence that conveys no authority to take action."""

    query: str
    trust_classification: Literal["untrusted_web_evidence"]
    results: tuple[UntrustedSearchResult, ...]


def search_flights(query: str) -> dict[str, object]:
    """Return JSON-ready, explicitly untrusted flight-search evidence.

    This is the public contract used by the discovery-agent CLI. It contains
    no authorization or execution fields by design.
    """

    evidence = discover_flights(query)
    return {
        "trust": PUBLIC_TRUST_MARKER,
        "query": evidence.query,
        "results": [
            {
                "name": result.name,
                "url": result.url,
                "content": result.content,
                "type": result.result_type,
            }
            for result in evidence.results
        ],
    }


def discover_flights(
    query: str,
    *,
    depth: str = "standard",
    timeout_seconds: float = 20.0,
) -> FlightDiscoveryEvidence:
    """Search the live web for flight evidence without performing any action.

    Linkup's raw ``searchResults`` output is preserved as explicitly untrusted
    evidence. This function cannot accept, derive, or return an authorization
    scope and cannot trigger booking or payment code.
    """

    normalized_query = query.strip()
    if not normalized_query:
        raise ValueError("query must not be empty")
    if depth not in _VALID_DEPTHS:
        raise ValueError("depth must be one of: fast, standard, deep")

    api_key = os.getenv("LINKUP_API_KEY", "").strip()
    if not api_key:
        raise LinkupDiscoveryError("LINKUP_API_KEY is not configured")

    base_url = os.getenv(
        "LINKUP_API_BASE_URL", DEFAULT_LINKUP_API_BASE_URL
    ).strip().rstrip("/")
    if not base_url:
        raise LinkupDiscoveryError("LINKUP_API_BASE_URL is empty")

    try:
        response = requests.post(
            f"{base_url}/v1/search",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "q": normalized_query,
                "depth": depth,
                "outputType": "searchResults",
            },
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise LinkupDiscoveryError("Linkup flight discovery failed") from exc

    raw_results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(raw_results, list):
        raise LinkupDiscoveryError("Linkup returned an invalid search response")

    results = tuple(_parse_untrusted_result(item) for item in raw_results)
    return FlightDiscoveryEvidence(
        query=normalized_query,
        trust_classification=TRUST_CLASSIFICATION,
        results=results,
    )


def _parse_untrusted_result(item: object) -> UntrustedSearchResult:
    if not isinstance(item, dict):
        raise LinkupDiscoveryError("Linkup returned an invalid search result")

    return UntrustedSearchResult(
        name=_string_field(item, "name"),
        url=_string_field(item, "url"),
        content=_string_field(item, "content"),
        result_type=_string_field(item, "type"),
    )


def _string_field(item: dict[object, object], field: str) -> str:
    value = item.get(field, "")
    return value if isinstance(value, str) else ""
