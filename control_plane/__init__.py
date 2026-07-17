"""Warden agent control plane.

The main service is imported lazily so read-only surfaces such as the public
showcase do not initialize or import the credential-bearing control plane.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import ControlPlane

__all__ = ["ControlPlane"]


def __getattr__(name: str) -> Any:
    if name == "ControlPlane":
        from .service import ControlPlane

        return ControlPlane
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
