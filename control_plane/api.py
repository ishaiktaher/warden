"""FastAPI REST, MCP and A2A facades for the Warden action gateway."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from .crypto import CapabilityError
from .auth import AuthenticationError, OIDCAuthenticator, Principal
from .schemas import (
    A2AMessage, ActionRequest, AgentManifest, ApprovalResolve, CapabilityDelegate,
    CapabilityIssue, ConnectorManifest, DemoRun, KillSwitchRequest, MCPToolCall,
    PolicyCreate, RevokeRequest, RunCreate, SecretStore, StatusUpdate, TaskCreate,
    ConnectStart, GrantDelegate, ManagedConnectionCreate, OAuthProviderCreate,
    OwnerCreate, ReconcileRequest,
)
from .credentials import CredentialError
from .service import ControlPlane, ControlPlaneError
from .observability import configure_observability
from .integrations import catalog, catalog_summary, get_integration


ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(
    title="Warden Agent Control Plane",
    version="0.1.0",
    description="Identity, capability, policy, secret, connector and audit control plane for AI agents.",
)
plane = ControlPlane()
authenticator = OIDCAuthenticator(plane.settings)
configure_observability(app, plane.settings)
if plane.settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(plane.settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )


@app.middleware("http")
async def production_identity_scope(request: Request, call_next):
    public_path = request.url.path in {
        "/", "/index.html", "/console", "/console.html", "/health", "/live", "/ready", "/documentation",
        "/docs.html", "/openapi.html", "/docs", "/openapi.json",
        "/onboarding", "/onboarding.js", "/policies", "/policies.js",
        "/connections", "/connections.js", "/warden-connect.js", "/product.css",
        "/.well-known/warden-keys", "/integrations", "/integrations/summary",
    } or (request.url.path.startswith("/integrations/") and request.method == "GET")
    oauth_callback = (
        request.method == "GET" and request.url.path.startswith("/oauth/")
        and request.url.path.endswith("/callback")
    )
    if not plane.settings.production or public_path or oauth_callback:
        return await call_next(request)
    try:
        principal = await run_in_threadpool(
            authenticator.authenticate, request.headers.get("Authorization")
        )
    except AuthenticationError as exc:
        return JSONResponse(status_code=401, content={"detail": str(exc)})
    request.state.principal = principal
    with plane.database.tenant_scope(principal.tenant_id):
        return await call_next(request)


def admin_actor(
    request: Request,
    x_admin_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    try:
        if plane.settings.production:
            principal = request.state.principal
            principal.require_any_role("warden:admin")
            return principal.subject
        return plane.require_admin(x_admin_key)
    except (ControlPlaneError, AuthenticationError) as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None


def owner_actor(
    request: Request,
    x_owner_id: Annotated[str | None, Header()] = None,
    x_owner_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    try:
        if plane.settings.production:
            principal = request.state.principal
            principal.require_any_role("warden:agent-owner", "warden:admin")
            return principal.tenant_id
        return plane.authenticate_owner(x_owner_id, x_owner_key)
    except (ControlPlaneError, AuthenticationError) as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None


def runtime_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal | None:
    if not plane.settings.production:
        return None
    try:
        principal = request.state.principal
        principal.require_any_role("warden:runtime", "warden:admin")
        return principal
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None


def audit_actor(request: Request) -> str:
    if not plane.settings.production:
        return "local-auditor"
    try:
        principal = request.state.principal
        principal.require_any_role("warden:auditor", "warden:admin")
        return principal.subject
    except AuthenticationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from None


def guarded(call):
    try:
        return call()
    except (ControlPlaneError, CapabilityError, CredentialError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(ROOT / "ui" / "index.html")


@app.get("/index.html", include_in_schema=False)
def dashboard_alias() -> FileResponse:
    return dashboard()


@app.get("/console", include_in_schema=False)
@app.get("/console.html", include_in_schema=False)
def management_console() -> FileResponse:
    return dashboard()


@app.get("/onboarding", include_in_schema=False)
def onboarding() -> FileResponse:
    return FileResponse(ROOT / "ui" / "onboarding.html")


@app.get("/onboarding.js", include_in_schema=False)
def onboarding_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "onboarding.js", media_type="text/javascript")


@app.get("/policies", include_in_schema=False)
def policy_builder() -> FileResponse:
    return FileResponse(ROOT / "ui" / "policies.html")


@app.get("/policies.js", include_in_schema=False)
def policy_builder_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "policies.js", media_type="text/javascript")


@app.get("/connections", include_in_schema=False)
def connection_wallet() -> FileResponse:
    return FileResponse(ROOT / "ui" / "connections.html")


@app.get("/connections.js", include_in_schema=False)
def connection_wallet_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "connections.js", media_type="text/javascript")


@app.get("/warden-connect.js", include_in_schema=False)
def connect_component_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "warden-connect.js", media_type="text/javascript")


@app.get("/product.css", include_in_schema=False)
def product_styles() -> FileResponse:
    return FileResponse(ROOT / "ui" / "product.css", media_type="text/css")


@app.get("/documentation", include_in_schema=False)
def documentation() -> FileResponse:
    return FileResponse(ROOT / "ui" / "docs.html")


@app.get("/docs.html", include_in_schema=False)
def documentation_file_alias() -> FileResponse:
    return documentation()


@app.get("/openapi.html", include_in_schema=False)
def openapi_landing() -> FileResponse:
    return FileResponse(ROOT / "ui" / "openapi.html")


@app.get("/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> JSONResponse:
    try:
        plane.database.one("SELECT 1 AS ready")
        if plane.settings.production and plane.rate_limiter.redis:
            plane.rate_limiter.redis.ping()
        return JSONResponse({"status": "ready"})
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready"})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "warden-agent-control-plane"}


@app.get("/integrations/summary")
def integration_summary() -> dict:
    return catalog_summary()


@app.get("/integrations")
def integrations(
    kind: str | None = Query(default=None, pattern="^(oauth2|managed_secret)$"),
    query: str | None = Query(default=None, max_length=100),
) -> list[dict]:
    return catalog(kind=kind, query=query)


@app.get("/integrations/{integration_id:path}")
def integration(integration_id: str) -> dict:
    found = get_integration(integration_id)
    if not found:
        raise HTTPException(status_code=404, detail="Unknown integration")
    return found


@app.get("/admin/status")
def admin_status(_: Annotated[str, Depends(admin_actor)]) -> dict:
    return {
        "environment": plane.settings.environment,
        "kill_switch": plane.kill_switch_enabled(),
        "integrations": catalog_summary(),
    }


@app.post("/admin/demo/bootstrap")
def bootstrap(_: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.bootstrap_support_demo())


@app.post("/admin/owners")
def create_owner(request: OwnerCreate, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.create_owner(request.owner_id, request.name, request.roles, actor))


@app.get("/owners/agents")
def owner_agents(owner: Annotated[str, Depends(owner_actor)]) -> list[dict]:
    return plane.owner_agents(owner)


@app.post("/owners/agents")
def owner_register_agent(
    request: AgentManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(status_code=403, detail="Agent owner must match authenticated owner")
    return guarded(lambda: plane.register_agent(request.model_dump(), owner))


@app.put("/owners/agents/{agent_id}")
def owner_update_agent(
    agent_id: str, request: AgentManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(status_code=403, detail="Agent owner must match authenticated owner")
    return guarded(lambda: plane.update_agent(agent_id, request.model_dump(), owner))


@app.post("/owners/connectors")
def owner_register_connector(
    request: ConnectorManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(status_code=403, detail="Connector owner must match authenticated owner")
    manifest = request.model_dump()
    manifest["status"] = "pending"
    return guarded(lambda: plane.register_connector(manifest, owner))


@app.post("/admin/demo/support-ticket")
def support_demo(request: DemoRun, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.run_support_ticket_scenario(request.principal_id, actor))


@app.post("/admin/agents")
def register_agent(request: AgentManifest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.register_agent(request.model_dump(), actor))


@app.get("/admin/agents")
def agents(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_agents()


@app.post("/admin/agents/{agent_id}/approve")
def approve_agent(agent_id: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.approve_agent(agent_id, actor))


@app.post("/admin/agents/{agent_id}/status")
def agent_status(agent_id: str, request: StatusUpdate, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.set_agent_status(agent_id, request.status, actor))


@app.post("/runs")
def create_run(
    request: RunCreate, principal: Annotated[Principal | None, Depends(runtime_principal)]
) -> dict:
    payload = request.model_dump()
    if principal:
        if "warden:admin" not in principal.roles and request.agent_id != principal.subject:
            raise HTTPException(status_code=403, detail="Runtime identity does not match agent")
        payload["principal_id"] = principal.on_behalf_of or principal.subject
    return guarded(lambda: plane.create_run(**payload))


@app.post("/tasks")
def create_task(
    request: TaskCreate, principal: Annotated[Principal | None, Depends(runtime_principal)]
) -> dict:
    if principal and "warden:admin" not in principal.roles:
        run = plane.database.one("SELECT agent_id FROM runs WHERE run_id=?", (request.run_id,))
        if not run or run["agent_id"] != principal.subject:
            raise HTTPException(status_code=403, detail="Runtime identity does not own the run")
    return guarded(lambda: plane.create_task(**request.model_dump()))


@app.post("/admin/capabilities/issue")
def issue_capability(request: CapabilityIssue, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    token, claims = guarded(lambda: plane.issue_capability(**request.model_dump(), actor=actor))
    return {"capability_token": token, "claims": claims}


@app.post("/capabilities/delegate")
def delegate_capability(
    request: CapabilityDelegate,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    if principal and "warden:admin" not in principal.roles:
        claims = guarded(lambda: plane.capabilities.verify(request.parent_token))
        if claims["agent_id"] != principal.subject:
            raise HTTPException(status_code=403, detail="Runtime identity does not own the parent capability")
    token, claims = guarded(lambda: plane.delegate_capability(**request.model_dump()))
    return {"capability_token": token, "claims": claims}


@app.post("/admin/capabilities/{jti}/revoke")
def revoke_capability(jti: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.revoke_token(jti, actor, request.reason))
    return {"status": "revoked", "jti": jti}


@app.post("/admin/runs/{run_id}/revoke")
def revoke_run(run_id: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.revoke_run(run_id, actor, request.reason))
    return {"status": "revoked", "run_id": run_id}


@app.post("/admin/keys/rotate")
def rotate_key(actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return {"kid": plane.capabilities.rotate_key(actor), "algorithm": "RS256"}


@app.post("/admin/keys/{kid}/revoke")
def revoke_key(kid: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.capabilities.revoke_key(kid, actor, request.reason))
    return {"kid": kid, "status": "revoked"}


@app.get("/.well-known/warden-keys")
def public_keys() -> list[dict[str, str]]:
    return plane.capabilities.public_keys()


@app.post("/admin/connectors")
def register_connector(request: ConnectorManifest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.register_connector(request.model_dump(), actor))


@app.get("/admin/connectors")
def connectors(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_connectors()


@app.post("/admin/connectors/{connector_id}/status")
def connector_status(connector_id: str, request: StatusUpdate, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.set_connector_status(connector_id, request.status, actor))


@app.post("/admin/policies")
def create_policy(request: PolicyCreate, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.seed_policy(
        request.rules, actor, request.policy_id, request.layer, request.target_id
    ))


@app.get("/admin/policies")
def policies(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_policies()


@app.post("/admin/oauth/providers/github")
def configure_github(
    request: OAuthProviderCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(lambda: plane.credentials.register_github_provider(
        client_id=request.client_id,
        client_secret_alias=request.client_secret_alias,
        default_scopes=request.default_scopes,
        owner=actor,
    ))


@app.post("/admin/oauth/providers/{provider_id}")
def configure_oauth_provider(
    provider_id: str, request: OAuthProviderCreate,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    if provider_id != request.provider_id:
        raise HTTPException(status_code=400, detail="Provider ID does not match route")
    required = {
        "authorization_url": request.authorization_url,
        "token_url": request.token_url,
        "api_base_url": request.api_base_url,
        "identity_url": request.identity_url,
    }
    if not all(required.values()):
        raise HTTPException(
            status_code=400,
            detail="Custom OAuth providers require authorization, token, API base and identity URLs",
        )
    return guarded(lambda: plane.credentials.register_oauth_provider(
        provider_id=provider_id, client_id=request.client_id,
        client_secret_alias=request.client_secret_alias,
        authorization_url=request.authorization_url or "",
        token_url=request.token_url or "", api_base_url=request.api_base_url or "",
        identity_url=request.identity_url or "",
        identity_id_field=request.identity_id_field,
        identity_label_field=request.identity_label_field,
        scope_separator=request.scope_separator,
        default_scopes=request.default_scopes, owner=actor,
    ))


@app.post("/admin/connections/managed")
def create_managed_connection(
    request: ManagedConnectionCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(lambda: plane.credentials.create_managed_connection(
        **request.model_dump(), actor=actor
    ))


@app.post("/connect/github/start")
def start_github_connect(request: Request, body: ConnectStart) -> dict:
    principal_id = body.principal_id
    if plane.settings.production:
        principal_id = request.state.principal.subject
    payload = body.model_dump()
    payload["principal_id"] = principal_id
    return guarded(lambda: plane.credentials.start_github_connect(**payload))


@app.post("/connect/{provider_id}/start")
def start_oauth_connect(provider_id: str, request: Request, body: ConnectStart) -> dict:
    principal_id = body.principal_id
    if plane.settings.production:
        principal_id = request.state.principal.subject
    payload = body.model_dump()
    payload["principal_id"] = principal_id
    return guarded(lambda: plane.credentials.start_oauth_connect(
        provider_id=provider_id, **payload
    ))


def _oauth_result(request: Request, result: dict) -> dict | HTMLResponse:
    if "text/html" not in request.headers.get("accept", ""):
        return result
    provider = escape(str(result["connection"]["provider_id"]))
    account = escape(str(result["connection"]["account_identifier"]))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Connection complete</title><style>body{{font:16px system-ui;background:#07111f;
    color:#edf5ff;display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:520px;
    padding:32px;border:1px solid #27405d;border-radius:16px;background:#0d1b2d}}a{{color:#64a8ff}}</style>
    </head><body><main><h1>Connection complete</h1><p>{provider} account
    <strong>{account}</strong> is now held by Warden.</p><p>You can close this window or
    <a href="/connections">manage connections</a>.</p></main></body></html>"""
    return HTMLResponse(page)


@app.get("/oauth/github/callback", response_model=None)
def github_callback(request: Request, code: str, state: str) -> dict | HTMLResponse:
    def complete() -> dict:
        tenant = plane.credentials.oauth_state_tenant(state)
        with plane.database.tenant_scope(tenant):
            return plane.credentials.complete_github_connect(code=code, state=state)
    return _oauth_result(request, guarded(complete))


@app.get("/oauth/{provider_id}/callback", response_model=None)
def oauth_callback(
    request: Request, provider_id: str, code: str, state: str,
) -> dict | HTMLResponse:
    def complete() -> dict:
        tenant = plane.credentials.oauth_state_tenant(state)
        with plane.database.tenant_scope(tenant):
            return plane.credentials.complete_oauth_connect(
                provider_id=provider_id, code=code, state=state
            )
    return _oauth_result(request, guarded(complete))


def _connection_principal(request: Request, principal_id: str | None) -> str:
    if plane.settings.production:
        return request.state.principal.subject
    if not principal_id:
        raise HTTPException(status_code=400, detail="principal_id is required locally")
    return principal_id


@app.get("/me/connections")
def my_connections(request: Request, principal_id: str | None = None) -> list[dict]:
    return plane.credentials.connections_for(_connection_principal(request, principal_id))


@app.get("/me/grants")
def my_grants(request: Request, principal_id: str | None = None) -> list[dict]:
    return plane.credentials.grants_for(_connection_principal(request, principal_id))


@app.post("/me/grants/{grant_id}/delegate")
def delegate_grant(
    grant_id: str, body: GrantDelegate, request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    return guarded(lambda: plane.credentials.delegate_grant(
        grant_id, body.agent_id, actor, body.reason
    ))


@app.post("/me/grants/{grant_id}/revoke")
def revoke_grant(
    grant_id: str, body: RevokeRequest, request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    guarded(lambda: plane.credentials.revoke_grant(grant_id, actor, body.reason))
    return {"status": "revoked", "grant_id": grant_id}


@app.post("/me/connections/{connection_id}/revoke")
def revoke_connection(
    connection_id: str, body: RevokeRequest, request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    guarded(lambda: plane.credentials.revoke_connection(connection_id, actor, body.reason))
    return {"status": "revoked", "connection_id": connection_id}


@app.post("/admin/policies/{policy_id}/revoke")
def revoke_policy(policy_id: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.revoke_policy(policy_id, actor, request.reason))
    return {"status": "revoked", "policy_id": policy_id}


@app.post("/admin/secrets")
def store_secret(request: SecretStore, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.secrets.store(request.alias, request.value, actor, request.provider))
    return {"status": "stored", "alias": request.alias}


@app.post("/admin/secrets/{alias}/revoke")
def revoke_secret(alias: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.secrets.revoke(alias, actor))
    return {"status": "revoked", "alias": alias}


@app.get("/admin/approvals")
def approvals(_: Annotated[str, Depends(admin_actor)], status: str | None = None) -> list[dict]:
    return plane.approvals(status)


@app.post("/admin/approvals/{approval_id}/resolve")
def resolve_approval(approval_id: str, request: ApprovalResolve, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.resolve_approval(approval_id, request.approved, actor, request.reason))


@app.post("/admin/kill-switch")
def kill_switch(request: KillSwitchRequest, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.set_kill_switch(request.enabled, actor))
    return {"enabled": request.enabled}


def execute(request: ActionRequest, principal: Principal | None = None) -> dict:
    payload = request.model_dump()
    payload["token"] = payload.pop("capability_token")
    if principal and "warden:admin" not in principal.roles:
        claims = guarded(lambda: plane.capabilities.verify(payload["token"]))
        if claims["agent_id"] != principal.subject:
            raise HTTPException(status_code=403, detail="Runtime identity does not own the capability")
    return plane.execute_action(**payload)


@app.post("/actions/execute")
def execute_rest(
    request: ActionRequest,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    return execute(request, principal)


@app.post("/mcp/tools/call")
def execute_mcp(
    request: MCPToolCall,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    return {"protocol": "mcp", "result": execute(request.params, principal)}


@app.post("/a2a/message:send")
def execute_a2a(
    request: A2AMessage,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    return {"protocol": "a2a", "result": execute(request.action_request, principal)}


@app.get("/audit/events")
def audit_events(
    _: Annotated[str, Depends(audit_actor)],
    run_id: str | None = None, principal_id: str | None = None,
    agent_id: str | None = None, event_type: str | None = None,
    decision: str | None = None, action: str | None = None,
    resource: str | None = None,
    limit: int = Query(default=200, ge=1, le=5000),
) -> list[dict]:
    return plane.audit.events(
        run_id=run_id, principal_id=principal_id, agent_id=agent_id,
        event_type=event_type, decision=decision, action=action,
        resource=resource, limit=limit,
    )


@app.get("/audit/verify")
def verify_audit(_: Annotated[str, Depends(audit_actor)]) -> dict:
    return plane.audit.verify()


@app.post("/admin/audit/anchor")
def anchor_audit(actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.audit.anchor(actor))


@app.post("/admin/maintenance/reconcile")
def reconcile_operations(
    request: ReconcileRequest, actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    return guarded(lambda: plane.reconcile_stale_operations(
        actor, request.stale_after_seconds
    ))


@app.get("/audit/export.ndjson")
def export_audit(
    _: Annotated[str, Depends(audit_actor)], run_id: str | None = None
) -> StreamingResponse:
    return StreamingResponse(
        plane.audit.export_ndjson(run_id=run_id), media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=warden-audit.ndjson"},
    )
