"""Read-only public surface for documentation and product evaluation.

This application deliberately does not import or instantiate the control plane.
It is safe to run on a public serverless host without database, Redis, OIDC,
signing, secret-custody, or audit-provider credentials.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse


ROOT = Path(__file__).resolve().parents[1]

app = FastAPI(
    title="Warden Public Showcase",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def public_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "public, max-age=300"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://www.vouchins.com; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
def showcase() -> FileResponse:
    return FileResponse(ROOT / "ui" / "showcase.html")


@app.get("/showcase.js", include_in_schema=False)
def showcase_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "showcase.js", media_type="text/javascript")


@app.get("/documentation", include_in_schema=False)
@app.get("/docs.html", include_in_schema=False)
def documentation() -> FileResponse:
    return FileResponse(ROOT / "ui" / "docs.html")


@app.get("/openapi.html", include_in_schema=False)
def openapi_landing() -> FileResponse:
    return FileResponse(ROOT / "ui" / "openapi.html")


@app.get("/health")
@app.get("/live")
@app.get("/ready")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "warden-public-showcase",
        "mode": "read-only",
    }
