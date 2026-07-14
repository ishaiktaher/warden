"""Vercel entrypoint. Durable production deployments must configure external storage."""

import os
from pathlib import Path
import tempfile


if os.getenv("VERCEL"):
    ephemeral_data = Path(tempfile.gettempdir()) / "warden-control-plane"
    os.environ.setdefault("CONTROL_PLANE_DATA_DIR", str(ephemeral_data))
    os.environ.setdefault("CONTROL_PLANE_ENV", "prod")

from control_plane.api import app  # noqa: E402,F401
