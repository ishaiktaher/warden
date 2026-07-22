"""Dedicated local portal entrypoint with an unmistakably synthetic GitHub OAuth transport.

Production starts ``control_plane.api:app`` and therefore never imports or mounts this
module. Local portal development starts ``control_plane.dev_portal:app``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from . import api as core


class _FixtureResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"Synthetic provider returned {self.status_code}")


class DevGitHubOAuthTransport:
    """In-process fixture transport; intentionally unavailable from production app."""

    def __init__(self) -> None:
        self.synthetic = True

    def post(self, url: str, **kwargs: Any) -> _FixtureResponse:
        del kwargs
        if url.endswith("/_dev/mock/github/token"):
            self._audit("token", url)
            return _FixtureResponse(
                {
                    "access_token": "synthetic-github-token",
                    "token_type": "bearer",
                    "scope": "repo",
                }
            )
        raise RuntimeError("Development OAuth transport blocked an unknown endpoint")

    def get(self, url: str, **kwargs: Any) -> _FixtureResponse:
        del kwargs
        if url.endswith("/_dev/mock/github/user"):
            self._audit("identity", url)
            return _FixtureResponse({"id": 4242, "login": "synthetic-octocat"})
        raise RuntimeError("Development OAuth transport blocked an unknown endpoint")

    def delete(self, url: str, **kwargs: Any) -> _FixtureResponse:
        del kwargs
        if "/applications/" in url:
            self._audit("revocation", url)
            return _FixtureResponse({}, 204)
        raise RuntimeError("Development OAuth transport blocked an unknown endpoint")

    @staticmethod
    def _audit(stage: str, url: str) -> None:
        core.plane.audit.append(
            "dev.mock_provider_response",
            "dev-github-transport",
            payload={
                "provider_id": "github",
                "stage": stage,
                "synthetic": True,
                "endpoint": url,
            },
        )


def create_dev_app() -> FastAPI:
    dev = FastAPI(title="Warden portal development profile", docs_url=None)
    core.plane.credentials.http = DevGitHubOAuthTransport()

    @dev.get("/_dev/mock/github/authorize", include_in_schema=False)
    def authorize(redirect_uri: str, state: str) -> RedirectResponse:
        core.plane.audit.append(
            "dev.mock_provider_response",
            "dev-github-transport",
            payload={
                "provider_id": "github",
                "stage": "authorization",
                "synthetic": True,
            },
        )
        return RedirectResponse(
            redirect_uri + "?" + urlencode({"code": "synthetic-code", "state": state})
        )

    dev.mount("/", core.app)
    return dev


app = create_dev_app()
