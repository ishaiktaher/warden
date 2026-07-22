"""Strict API contracts for the control plane."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AgentManifest(StrictModel):
    agent_id: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=200)
    owner: str = Field(min_length=2, max_length=200)
    purpose: str = Field(min_length=2, max_length=1000)
    model_provider: str = Field(min_length=2, max_length=200)
    agent_version: str = Field(min_length=1, max_length=100)
    environment: Literal["dev", "test", "prod"]
    risk_tier: Literal["low", "medium", "high", "critical"]
    allowed_tools: list[str] = Field(max_length=100)
    allowed_actions: list[str] = Field(max_length=200)
    allowed_data_classifications: list[
        Literal["public", "internal", "sensitive", "restricted"]
    ] = Field(max_length=4)
    max_delegation_depth: int = Field(ge=0, le=10)
    approved_parents: list[str] = Field(default_factory=list, max_length=100)
    approved_children: list[str] = Field(default_factory=list, max_length=100)
    expires_at: str | None = None
    review_date: str | None = None
    owner_signature: str | None = None


class StatusUpdate(StrictModel):
    status: str
    reason: str = ""


class RunCreate(StrictModel):
    principal_id: str = Field(min_length=2, max_length=200)
    agent_id: str
    task: str = Field(min_length=2, max_length=2000)
    environment: Literal["dev", "test", "prod"]
    parent_run_id: str | None = None


class TaskCreate(StrictModel):
    run_id: str
    description: str = Field(min_length=2, max_length=2000)
    parent_task_id: str | None = None


class CapabilityIssue(StrictModel):
    run_id: str
    scopes: list[str] = Field(min_length=1, max_length=200)
    resources: list[str] = Field(min_length=1, max_length=200)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


class CapabilityDelegate(StrictModel):
    parent_token: str = Field(min_length=100, max_length=16_384)
    parent_runtime_proof: str = Field(min_length=20, max_length=200)
    child_run_id: str
    scopes: list[str] = Field(min_length=1, max_length=200)
    resources: list[str] = Field(min_length=1, max_length=200)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


class ConnectorManifest(StrictModel):
    connector_id: str = Field(min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    tool: str = Field(min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    action: str = Field(min_length=3, max_length=200, pattern=r"^[a-zA-Z0-9_.:-]+$")
    adapter_type: Literal[
        "local",
        "local_emulator",
        "rest",
        "mcp_upstream",
        "a2a_upstream",
        "github_readonly",
        "database",
        "shell_sandbox",
        "browser_sandbox",
    ]
    endpoint: str | None = None
    http_method: str | None = None
    resource_patterns: list[str] = Field(min_length=1, max_length=200)
    required_scopes: list[str] = Field(max_length=200)
    secret_alias: str | None = None
    status: Literal["pending", "active", "suspended", "retired"] = "active"
    owner: str
    risk_tier: Literal["low", "medium", "high", "critical"]
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10000)
    credential_mode: Literal[
        "bearer", "custom_header", "basic", "multi_header", "query", "aws_sigv4"
    ] = "bearer"
    credential_config: dict[str, Any] = Field(default_factory=dict, max_length=100)
    grant_required: bool = False


class PolicyCreate(StrictModel):
    policy_id: str = "default"
    layer: Literal["platform", "tenant", "agent", "connector", "grant"] = "platform"
    target_id: str = "*"
    rules: dict[str, Any]


class OAuthProviderCreate(StrictModel):
    provider_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,99}$")
    client_id: str = Field(min_length=5, max_length=200)
    client_secret_alias: str = Field(min_length=2, max_length=200)
    authorization_url: str | None = Field(default=None, max_length=2000)
    token_url: str | None = Field(default=None, max_length=2000)
    api_base_url: str | None = Field(default=None, max_length=2000)
    identity_url: str | None = Field(default=None, max_length=2000)
    identity_id_field: str = Field(default="id", pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    identity_label_field: str = Field(
        default="name", pattern=r"^[A-Za-z0-9_.-]{1,100}$"
    )
    scope_separator: Literal[" ", ","] = " "
    default_scopes: list[str] = Field(default_factory=list, max_length=200)


class ConnectStart(StrictModel):
    principal_id: str = Field(min_length=2, max_length=200)
    agent_id: str | None = None
    label: str = Field(default="default", min_length=1, max_length=100)
    provider_scopes: list[str] = Field(default_factory=list, max_length=200)
    grant_scopes: list[str] = Field(min_length=1, max_length=200)
    allowed_methods: list[str] = Field(default_factory=list, max_length=10)
    path_patterns: list[str] = Field(default_factory=lambda: ["/*"], max_length=200)
    ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    reason: str = Field(min_length=2, max_length=1000)


class ConnectSessionCreate(StrictModel):
    principal_id: str = Field(min_length=2, max_length=200)
    agent_id: str | None = None
    allowed_providers: list[str] = Field(min_length=1, max_length=10)
    provider_scopes: list[str] = Field(default_factory=list, max_length=200)
    grant_scopes: list[str] = Field(min_length=1, max_length=200)
    allowed_methods: list[str] = Field(default_factory=list, max_length=10)
    path_patterns: list[str] = Field(default_factory=lambda: ["/*"], max_length=200)
    label: str = Field(default="default", min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=1000)
    ttl_seconds: int = Field(default=600, ge=60, le=600)


class ConnectSessionToken(StrictModel):
    session_token: str = Field(min_length=40, max_length=16_384)


class APIKeyCreate(StrictModel):
    key_type: Literal["runtime", "agent", "derived"]
    name: str = Field(min_length=1, max_length=100)
    scopes: list[str] = Field(min_length=1, max_length=100)
    agent_id: str | None = None
    expires_in: int | None = Field(default=None, ge=60, le=31_536_000)
    cidr_allowlist: list[str] = Field(default_factory=list, max_length=50)
    parent_key_id: str | None = None


class AppCreate(StrictModel):
    app_id: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=200)


class AppIdentityProviderCreate(StrictModel):
    issuer: str = Field(min_length=8, max_length=2000)
    client_id: str = Field(min_length=2, max_length=500)
    client_secret_alias: str = Field(min_length=2, max_length=200)
    user_id_claim: str = Field(default="sub", pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    email_claim: str = Field(default="email", pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    groups_claim: str = Field(default="groups", pattern=r"^[A-Za-z0-9_.-]{1,100}$")


class IdentityResolve(StrictModel):
    id_token: str = Field(min_length=40, max_length=16_384)


class DeprovisionEvent(StrictModel):
    event_id: str = Field(min_length=4, max_length=200)
    event_type: Literal["user.deprovisioned"]
    external_subject_id: str = Field(min_length=1, max_length=500)


class ManagedConnectionCreate(StrictModel):
    provider_id: str = Field(min_length=2, max_length=100)
    owner_principal_id: str = Field(min_length=2, max_length=200)
    account_identifier: str = Field(min_length=1, max_length=500)
    credential: dict[str, Any] = Field(min_length=1, max_length=100)
    principal_type: Literal["user", "group", "system", "agent"]
    principal_id: str = Field(min_length=2, max_length=200)
    label: str = Field(default="default", min_length=1, max_length=100)
    grant_scopes: list[str] = Field(min_length=1, max_length=200)
    allowed_methods: list[str] = Field(default_factory=list, max_length=10)
    path_patterns: list[str] = Field(default_factory=lambda: ["/*"], max_length=200)
    ttl_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    reason: str = Field(min_length=2, max_length=1000)


class GrantDelegate(StrictModel):
    agent_id: str
    reason: str = Field(min_length=2, max_length=1000)


class SecretStore(StrictModel):
    alias: str
    value: str
    provider: str = "local-encrypted"


class ApprovalResolve(StrictModel):
    approved: bool
    reason: str = ""


class RevokeRequest(StrictModel):
    reason: str = Field(min_length=2, max_length=1000)


class KillSwitchRequest(StrictModel):
    enabled: bool


class ActionRequest(StrictModel):
    capability_token: str = Field(min_length=100, max_length=16_384)
    runtime_proof: str = Field(min_length=20, max_length=200)
    request_nonce: str = Field(min_length=8, max_length=200)
    task_id: str = Field(min_length=1, max_length=200)
    connector_id: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(min_length=1, max_length=2_000)
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=1_000)
    data_classification: Literal["public", "internal", "sensitive", "restricted"] = (
        "internal"
    )
    environment: Literal["dev", "test", "prod"]
    approval_id: str | None = None
    grant_id: str | None = None
    risk_signals: dict[str, Any] = Field(default_factory=dict, max_length=100)


class MCPToolCall(StrictModel):
    method: Literal["tools/call"] = "tools/call"
    params: ActionRequest


class A2AMessage(StrictModel):
    message_type: Literal["message:send"] = "message:send"
    action_request: ActionRequest


class DemoRun(StrictModel):
    principal_id: str = "user-demo"


class OwnerCreate(StrictModel):
    owner_id: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=2, max_length=200)
    roles: list[str] = Field(default_factory=lambda: ["agent-owner"])


class ReconcileRequest(StrictModel):
    stale_after_seconds: int = Field(default=300, ge=60, le=86_400)
