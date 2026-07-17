"""Vercel entrypoint with a safe, read-only default surface.

Set ``WARDEN_VERCEL_MODE=control-plane`` only when every production dependency
documented in ``docs/PRODUCTION.md`` is configured. The default showcase mode
does not instantiate the control plane or expose management/action endpoints.
"""

import os


mode = os.getenv("WARDEN_VERCEL_MODE", "showcase").strip().lower()

if mode == "showcase":
    from control_plane.showcase import app  # noqa: F401
elif mode == "control-plane":
    os.environ["CONTROL_PLANE_ENV"] = "prod"
    from control_plane.api import app  # noqa: E402,F401
else:
    raise RuntimeError(
        "WARDEN_VERCEL_MODE must be 'showcase' or 'control-plane'"
    )
