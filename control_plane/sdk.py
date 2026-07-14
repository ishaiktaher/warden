"""Small SDK wrapper for any agent runtime that can call HTTP."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import requests


class WardenSDKError(RuntimeError):
    pass


@dataclass
class WardenClient:
    base_url: str
    timeout: float = 20.0
    access_token: str | None = None

    def create_run(self, *, principal_id: str, agent_id: str, task: str, environment: str, parent_run_id: str | None = None) -> dict[str, Any]:
        return self._post("/runs", {"principal_id": principal_id, "agent_id": agent_id, "task": task, "environment": environment, "parent_run_id": parent_run_id})

    def create_task(self, *, run_id: str, description: str, parent_task_id: str | None = None) -> dict[str, Any]:
        return self._post("/tasks", {"run_id": run_id, "description": description, "parent_task_id": parent_task_id})

    def execute(
        self, *, capability_token: str, task_id: str, connector_id: str,
        action: str, resource: str, environment: str, runtime_proof: str,
        parameters: dict[str, Any] | None = None,
        data_classification: str = "internal", approval_id: str | None = None,
        grant_id: str | None = None,
        risk_signals: dict[str, Any] | None = None, request_nonce: str | None = None,
    ) -> dict[str, Any]:
        return self._post("/actions/execute", {
            "capability_token": capability_token, "runtime_proof": runtime_proof,
            "request_nonce": request_nonce or str(uuid4()),
            "task_id": task_id, "connector_id": connector_id, "action": action,
            "resource": resource, "parameters": parameters or {},
            "data_classification": data_classification, "environment": environment,
            "approval_id": approval_id, "grant_id": grant_id,
            "risk_signals": risk_signals or {},
        })

    def start_github_connect(
        self, *, principal_id: str, grant_scopes: list[str], reason: str,
        agent_id: str | None = None, provider_scopes: list[str] | None = None,
        allowed_methods: list[str] | None = None,
        path_patterns: list[str] | None = None, label: str = "default",
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        return self._post("/connect/github/start", {
            "principal_id": principal_id, "agent_id": agent_id, "label": label,
            "provider_scopes": provider_scopes or [], "grant_scopes": grant_scopes,
            "allowed_methods": allowed_methods or [],
            "path_patterns": path_patterns or ["/*"],
            "ttl_seconds": ttl_seconds, "reason": reason,
        })

    def delegate(
        self, *, parent_token: str, parent_runtime_proof: str,
        child_run_id: str, scopes: list[str], resources: list[str],
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        return self._post("/capabilities/delegate", {
            "parent_token": parent_token,
            "parent_runtime_proof": parent_runtime_proof,
            "child_run_id": child_run_id, "scopes": scopes,
            "resources": resources, "ttl_seconds": ttl_seconds,
        })

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            headers = (
                {"Authorization": f"Bearer {self.access_token}"}
                if self.access_token else {}
            )
            response = requests.post(
                self.base_url.rstrip("/") + path, json=body,
                headers=headers, timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise WardenSDKError("Warden request failed") from exc
        if not isinstance(result, dict):
            raise WardenSDKError("Warden returned an invalid response")
        return result
