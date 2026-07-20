"""Dependency-free HTTP client for the Warden control plane."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4


class WardenError(RuntimeError):
    def __init__(self, message: str, *, status: int = 0, request_id: str | None = None):
        super().__init__(message)
        self.status = status
        self.request_id = request_id


Transport = Callable[
    [str, str, dict[str, str], bytes | None, float], tuple[int, dict[str, str], bytes]
]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


_OPENER = build_opener(_NoRedirect)


def _default_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, data=body, headers=headers, method=method)
    try:
        # Redirects are disabled so authorization cannot cross an origin boundary.
        with _OPENER.open(request, timeout=timeout) as response:  # nosec B310
            return response.status, dict(response.headers), response.read()
    except HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()
    except URLError as exc:
        raise WardenError("Warden is unavailable") from exc


@dataclass
class WardenClient:
    base_url: str
    access_token: str | None = None
    admin_key: str | None = None
    timeout: float = 20.0
    transport: Transport = _default_transport

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        local = parsed.hostname in {"localhost", "127.0.0.1"}
        if parsed.scheme != "https" and not (local and parsed.scheme == "http"):
            raise ValueError("Warden base_url must use HTTPS except on localhost")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Warden base_url contains forbidden URL components")
        if not isinstance(self.timeout, (int, float)) or self.timeout <= 0:
            raise ValueError("timeout must be positive")
        self.base_url = self.base_url.rstrip("/")

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def integrations(
        self, *, kind: str | None = None, query: str | None = None
    ) -> list[dict[str, Any]]:
        params = {
            key: value for key, value in {"kind": kind, "query": query}.items() if value
        }
        result = self._request(
            "GET", "/integrations" + (f"?{urlencode(params)}" if params else "")
        )
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid integration catalog")
        return result

    def agents(self) -> list[dict[str, Any]]:
        result = self._request("GET", "/admin/agents", admin=True)
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid agent list")
        return result

    def create_run(
        self,
        *,
        principal_id: str,
        agent_id: str,
        task: str,
        environment: str,
        parent_run_id: str | None = None,
    ) -> dict[str, Any]:
        return self._object(
            "POST",
            "/runs",
            {
                "principal_id": principal_id,
                "agent_id": agent_id,
                "task": task,
                "environment": environment,
                "parent_run_id": parent_run_id,
            },
        )

    def create_task(
        self, *, run_id: str, description: str, parent_task_id: str | None = None
    ) -> dict[str, Any]:
        return self._object(
            "POST",
            "/tasks",
            {
                "run_id": run_id,
                "description": description,
                "parent_task_id": parent_task_id,
            },
        )

    def issue_capability(
        self,
        *,
        run_id: str,
        scopes: list[str],
        resources: list[str],
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._object(
            "POST",
            "/admin/capabilities/issue",
            {
                "run_id": run_id,
                "scopes": scopes,
                "resources": resources,
                "ttl_seconds": ttl_seconds,
            },
            admin=True,
        )

    def execute(
        self,
        *,
        capability_token: str,
        runtime_proof: str,
        task_id: str,
        connector_id: str,
        action: str,
        resource: str,
        environment: str,
        parameters: dict[str, Any] | None = None,
        data_classification: str = "internal",
        approval_id: str | None = None,
        grant_id: str | None = None,
        risk_signals: dict[str, Any] | None = None,
        request_nonce: str | None = None,
    ) -> dict[str, Any]:
        return self._object(
            "POST",
            "/actions/execute",
            {
                "capability_token": capability_token,
                "runtime_proof": runtime_proof,
                "request_nonce": request_nonce or str(uuid4()),
                "task_id": task_id,
                "connector_id": connector_id,
                "action": action,
                "resource": resource,
                "parameters": parameters or {},
                "data_classification": data_classification,
                "environment": environment,
                "approval_id": approval_id,
                "grant_id": grant_id,
                "risk_signals": risk_signals or {},
            },
        )

    def start_connect(
        self,
        provider_id: str,
        *,
        principal_id: str,
        grant_scopes: list[str],
        reason: str,
        agent_id: str | None = None,
        provider_scopes: list[str] | None = None,
        allowed_methods: list[str] | None = None,
        path_patterns: list[str] | None = None,
        ttl_seconds: int | None = None,
        label: str = "default",
    ) -> dict[str, Any]:
        return self._object(
            "POST",
            f"/connect/{quote(provider_id, safe='')}/start",
            {
                "principal_id": principal_id,
                "agent_id": agent_id,
                "label": label,
                "provider_scopes": provider_scopes or [],
                "grant_scopes": grant_scopes,
                "allowed_methods": allowed_methods or [],
                "path_patterns": path_patterns or ["/*"],
                "ttl_seconds": ttl_seconds,
                "reason": reason,
            },
        )

    def connections(self, *, principal_id: str | None = None) -> list[dict[str, Any]]:
        suffix = f"?{urlencode({'principal_id': principal_id})}" if principal_id else ""
        result = self._request("GET", f"/me/connections{suffix}")
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid connection list")
        return result

    def grants(self, *, principal_id: str | None = None) -> list[dict[str, Any]]:
        suffix = f"?{urlencode({'principal_id': principal_id})}" if principal_id else ""
        result = self._request("GET", f"/me/grants{suffix}")
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid grant list")
        return result

    def audit_verify(self) -> dict[str, Any]:
        return self._object("GET", "/audit/verify")

    def _object(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        admin: bool = False,
    ) -> dict[str, Any]:
        result = self._request(method, path, body, admin=admin)
        if not isinstance(result, dict):
            raise WardenError("Warden returned an invalid response")
        return result

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        admin: bool = False,
    ) -> Any:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        elif admin and self.admin_key:
            headers["X-Admin-Key"] = self.admin_key
        payload = (
            json.dumps(body, separators=(",", ":")).encode()
            if body is not None
            else None
        )
        status, response_headers, raw = self.transport(
            method, self.base_url + path, headers, payload, self.timeout
        )
        try:
            result = json.loads(raw or b"null")
        except ValueError as exc:
            raise WardenError("Warden returned malformed JSON", status=status) from exc
        if not 200 <= status < 300:
            message = (
                result.get("detail", f"Warden request failed with HTTP {status}")
                if isinstance(result, dict)
                else f"Warden request failed with HTTP {status}"
            )
            raise WardenError(
                str(message),
                status=status,
                request_id=response_headers.get("X-Request-ID"),
            )
        return result
