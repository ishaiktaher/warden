"""Canonical resource identifiers used by capability and policy checks."""

from __future__ import annotations

import fnmatch
from urllib.parse import unquote, urlsplit, urlunsplit


class ResourceError(ValueError):
    pass


def canonical_resource(value: str, *, pattern: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ResourceError("Resource identifier is invalid")
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc or parsed.username or parsed.password:
        raise ResourceError("Resource must be an absolute authority URI")
    if parsed.query or parsed.fragment:
        raise ResourceError("Resource query strings and fragments are forbidden")
    decoded = unquote(parsed.path)
    if decoded != parsed.path:
        raise ResourceError("Percent-encoded resource paths are forbidden")
    segments = decoded.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise ResourceError("Resource path traversal is forbidden")
    if not pattern and any(char in value for char in "*?["):
        raise ResourceError("Concrete resources cannot contain wildcards")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), decoded, "", ""))


def resource_matches(resource: str, pattern: str) -> bool:
    concrete = canonical_resource(resource)
    allowed = canonical_resource(pattern, pattern=True)
    return fnmatch.fnmatchcase(concrete, allowed)
