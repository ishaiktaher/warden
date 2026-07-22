"""Dependency-free HTTP client for the Warden control plane."""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4


class WardenError(RuntimeError):
    code = "unknown"

    def __init__(
        self,
        message: str,
        *,
        status: int = 0,
        request_id: str | None = None,
        retryable: bool = False,
        code: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.request_id = request_id
        self.retryable = retryable
        if code:
            self.code = code


class InvalidRequestError(WardenError):
    code = "invalid_request"


class InvalidScopeError(WardenError):
    code = "invalid_scope"


class InvalidKeyError(WardenError):
    code = "invalid_key"


class ExpiredSessionError(WardenError):
    code = "expired_session"


class PolicyDeniedError(WardenError):
    code = "policy_denied"


class ApprovalRequiredError(WardenError):
    code = "approval_required"


class RevokedError(WardenError):
    code = "revoked"


class NotFoundError(WardenError):
    code = "not_found"


class ConflictError(WardenError):
    code = "conflict"


class UnauthorizedError(WardenError):
    code = "unauthorized"


class ForbiddenError(WardenError):
    code = "forbidden"


class ProviderError(WardenError):
    code = "provider_error"


class UnavailableError(WardenError):
    code = "unavailable"


ERROR_TYPES = {
    error.code: error
    for error in (
        InvalidRequestError,
        InvalidScopeError,
        InvalidKeyError,
        ExpiredSessionError,
        PolicyDeniedError,
        ApprovalRequiredError,
        RevokedError,
        NotFoundError,
        ConflictError,
        UnauthorizedError,
        ForbiddenError,
        ProviderError,
        UnavailableError,
    )
}


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
    api_key: str | None = None
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

    @property
    def apps(self) -> "App":
        return App(self)

    @property
    def agent_resources(self) -> "Agent":
        return Agent(self)

    @property
    def grant_resources(self) -> "Grant":
        return Grant(self)

    @property
    def keys(self) -> "Key":
        return Key(self)

    @property
    def approvals(self) -> "Approval":
        return Approval(self)

    @property
    def audit_logs(self) -> "AuditLog":
        return AuditLog(self)

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
        session = self._object(
            "POST",
            "/admin/connect/sessions",
            {
                "principal_id": principal_id,
                "agent_id": agent_id,
                "allowed_providers": [provider_id],
                "provider_scopes": provider_scopes or [],
                "grant_scopes": grant_scopes,
                "allowed_methods": allowed_methods or [],
                "path_patterns": path_patterns or ["/*"],
                "ttl_seconds": min(ttl_seconds or 600, 600),
                "reason": reason,
                "label": label,
            },
            admin=True,
        )
        return self._object(
            "POST",
            f"/connect/{quote(provider_id, safe='')}/start",
            {"session_token": session["session_token"]},
        )

    def mint_connect_session(self, **request: Any) -> dict[str, Any]:
        return self._object("POST", "/admin/connect/sessions", request, admin=True)

    def enforcement_trace(self, call_id: str) -> dict[str, Any]:
        return self._object("GET", f"/enforcement-traces/{quote(call_id, safe='')}")

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
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        result = self._request(
            method, path, body, admin=admin, extra_headers=extra_headers
        )
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
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        headers.update(extra_headers or {})
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        elif self.api_key and not admin:
            headers["X-Warden-Key"] = self.api_key
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
        content_type = next(
            (
                value
                for key, value in response_headers.items()
                if key.lower() == "content-type"
            ),
            "",
        )
        if 200 <= status < 300 and "text/csv" in content_type:
            return raw.decode()
        try:
            result = json.loads(raw or b"null")
        except ValueError as exc:
            raise WardenError("Warden returned malformed JSON", status=status) from exc
        if not 200 <= status < 300:
            envelope = result.get("error", {}) if isinstance(result, dict) else {}
            message = envelope.get(
                "detail", f"Warden request failed with HTTP {status}"
            )
            code = envelope.get("code", "unknown")
            error_type = ERROR_TYPES.get(code, WardenError)
            raise error_type(
                str(message),
                status=status,
                request_id=envelope.get("request_id")
                or response_headers.get("X-Request-ID"),
                retryable=bool(envelope.get("retryable", False)),
                code=code,
            )
        return result


class _Resource:
    def __init__(self, client: WardenClient):
        self.client = client


class App(_Resource):
    def create(self, app_id: str, name: str) -> dict[str, Any]:
        return self.client._object(
            "POST", "/admin/apps", {"app_id": app_id, "name": name}, admin=True
        )

    def list(self) -> list[dict[str, Any]]:
        result = self.client._request("GET", "/admin/apps", admin=True)
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid app list")
        return result

    def identity(self, app_id: str) -> dict[str, Any]:
        return self.client._object(
            "GET", f"/admin/apps/{quote(app_id, safe='')}/identity", admin=True
        )

    def users(self, app_id: str) -> list[dict[str, Any]]:
        result = self.client._request(
            "GET", f"/admin/apps/{quote(app_id, safe='')}/users", admin=True
        )
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid app-user list")
        return result

    def configure_identity(
        self, app_id: str, *, client_secret: str, **config: Any
    ) -> dict[str, Any]:
        alias = config["client_secret_alias"]
        self.client._object(
            "POST",
            "/admin/secrets",
            {"alias": alias, "value": client_secret, "provider": "local-encrypted"},
            admin=True,
        )
        return self.client._object(
            "POST",
            f"/admin/apps/{quote(app_id, safe='')}/identity-provider",
            config,
            admin=True,
        )


class Agent(_Resource):
    def list(self) -> list[dict[str, Any]]:
        return self.client.agents()

    def create(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.client._object("POST", "/admin/agents", request, admin=True)

    def approve(self, agent_id: str) -> dict[str, Any]:
        return self.client._object(
            "POST", f"/admin/agents/{quote(agent_id, safe='')}/approve", {}, admin=True
        )


class Grant(_Resource):
    def list(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        return self.client.grants(principal_id=principal_id)


class Key(_Resource):
    def mint(self, **request: Any) -> dict[str, Any]:
        return self.client._object("POST", "/admin/api-keys", request, admin=True)

    def list(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        suffix = f"?{urlencode({'agent_id': agent_id})}" if agent_id else ""
        result = self.client._request("GET", f"/admin/api-keys{suffix}", admin=True)
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid key list")
        return result

    def deprecate(self, key_id: str) -> dict[str, Any]:
        return self.client._object(
            "POST",
            f"/admin/api-keys/{quote(key_id, safe='')}/deprecate",
            {},
            admin=True,
        )

    def revoke(self, key_id: str) -> dict[str, Any]:
        return self.client._object(
            "POST", f"/admin/api-keys/{quote(key_id, safe='')}/revoke", {}, admin=True
        )


class Approval(_Resource):
    def list(self, approver_id: str, status: str = "pending") -> list[dict[str, Any]]:
        result = self.client._request(
            "GET",
            f"/approvals?{urlencode({'status': status})}",
            extra_headers={"X-Approver-ID": approver_id},
        )
        if not isinstance(result, list):
            raise WardenError("Warden returned an invalid approval list")
        return result

    def resolve(
        self, approval_id: str, approver_id: str, approved: bool, reason: str = ""
    ) -> dict[str, Any]:
        return self.client._object(
            "POST",
            f"/approvals/{quote(approval_id, safe='')}/resolve",
            {"approved": approved, "reason": reason},
            extra_headers={"X-Approver-ID": approver_id},
        )

    def await_result(
        self,
        approval_id: str,
        approver_id: str,
        timeout: float = 600,
        interval: float = 1,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.client._object(
                "GET",
                f"/approvals/{quote(approval_id, safe='')}",
                extra_headers={"X-Approver-ID": approver_id},
            )
            if result["status"] != "pending":
                return result
            time.sleep(interval)
        raise ExpiredSessionError("Approval wait timed out", code="expired_session")


class AuditLog(_Resource):
    def page(self, **filters: Any) -> dict[str, Any]:
        query = urlencode(
            {key: value for key, value in filters.items() if value is not None}
        )
        return self.client._object(
            "GET", f"/audit/events/page{f'?{query}' if query else ''}"
        )

    def export_csv(self, **filters: Any) -> str:
        query = urlencode(
            {key: value for key, value in filters.items() if value is not None}
        )
        result = self.client._request(
            "GET", f"/audit/export.csv{f'?{query}' if query else ''}"
        )
        if not isinstance(result, str):
            raise WardenError("Warden returned an invalid CSV export")
        return result
