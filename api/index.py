"""Cloud-safe Vercel entrypoint for the public Warden showcase."""

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="Warden Hosted Showcase")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "ui" / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "hosted_showcase"}
