"""Vercel entrypoint for Warden's read-only public surface.

The credential-bearing control plane is deliberately not selectable here. It
must be deployed from the OCI image with the production dependencies described
in ``docs/PRODUCTION.md``.
"""

from fastapi import FastAPI

from control_plane.showcase import app as showcase_app


# Vercel's detector requires a literal top-level FastAPI instance in a
# recognized entrypoint. Mounting the isolated showcase keeps all management
# and action routes out of the public serverless deployment.
app = FastAPI(
    title="Warden Public Showcase",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/", showcase_app)
