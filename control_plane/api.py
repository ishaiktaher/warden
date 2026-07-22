"""FastAPI REST, MCP and A2A facades for the Warden action gateway."""

from __future__ import annotations

from html import escape
import hashlib
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    StreamingResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from .crypto import CapabilityError
from .auth import AuthenticationError, OIDCAuthenticator, Principal
from .schemas import (
    A2AMessage,
    ActionRequest,
    AgentManifest,
    ApprovalResolve,
    CapabilityDelegate,
    CapabilityIssue,
    ConnectorManifest,
    DemoRun,
    KillSwitchRequest,
    MCPToolCall,
    PolicyCreate,
    RevokeRequest,
    RunCreate,
    SecretStore,
    StatusUpdate,
    TaskCreate,
    GrantDelegate,
    ManagedConnectionCreate,
    OAuthProviderCreate,
    OwnerCreate,
    ReconcileRequest,
    APIKeyCreate,
    AppCreate,
    AppIdentityProviderCreate,
    ConnectSessionCreate,
    ConnectSessionToken,
    IdentityResolve,
)
from .credentials import CredentialError
from .service import ControlPlane, ControlPlaneError
from .observability import configure_observability
from .integrations import PROVIDER_CONTRACTS, catalog, catalog_summary, get_integration
from .errors import WardenAPIError, classify


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


@app.exception_handler(WardenAPIError)
async def warden_error_handler(request: Request, exc: WardenAPIError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status, content=exc.body(request.headers.get("X-Request-ID"))
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    error = WardenAPIError("invalid_request", "Request validation failed")
    body = error.body(request.headers.get("X-Request-ID"))
    body["error"]["fields"] = exc.errors()
    return JSONResponse(status_code=422, content=body)


@app.exception_handler(HTTPException)
async def stable_http_error_handler(
    request: Request, exc: HTTPException
) -> JSONResponse:
    if isinstance(exc.detail, dict) and "error" in exc.detail:
        return await http_exception_handler(request, exc)
    error = classify(str(exc.detail), status=exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content=error.body(request.headers.get("X-Request-ID")),
    )


@app.middleware("http")
async def production_identity_scope(request: Request, call_next):
    authorization = request.headers.get("Authorization", "")
    bearer = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
    cookie_session = request.cookies.get("warden_session")
    session_token = bearer if bearer.startswith("wus_") else cookie_session
    if session_token:
        try:
            tenant = plane.identity.session_tenant(session_token)
            with plane.database.tenant_scope(tenant):
                session = plane.identity.authenticate_session(session_token)
                request.state.portal_session = session
                request.state.principal = Principal(
                    session["user_id"],
                    tenant,
                    frozenset({"warden:admin", "warden:runtime", "warden:auditor"}),
                    on_behalf_of=session["user_id"],
                )
                if cookie_session and request.method not in {"GET", "HEAD", "OPTIONS"}:
                    plane.identity.validate_csrf(
                        session, request.headers.get("X-CSRF-Token")
                    )
                return await call_next(request)
        except WardenAPIError as exc:
            return JSONResponse(
                status_code=exc.status,
                content=exc.body(request.headers.get("X-Request-ID")),
            )
    public_path = (
        request.url.path
        in {
            "/",
            "/index.html",
            "/console",
            "/console.html",
            "/health",
            "/live",
            "/ready",
            "/documentation",
            "/docs.html",
            "/openapi.html",
            "/docs",
            "/openapi.json",
            "/onboarding",
            "/onboarding.js",
            "/policies",
            "/policies.js",
            "/connections",
            "/connections.js",
            "/warden-connect.js",
            "/oauth-result.js",
            "/portal",
            "/portal.js",
            "/portal.css",
            "/sdk/warden.js",
            "/portal/session",
            "/portal/auth/callback",
            "/product.css",
            "/.well-known/warden-keys",
            "/integrations",
            "/integrations/summary",
        }
        or (request.url.path.startswith("/integrations/") and request.method == "GET")
        or (
            request.url.path.startswith("/portal/auth/login/")
            and request.method == "GET"
        )
    )
    oauth_callback = (
        request.method == "GET"
        and request.url.path.startswith("/oauth/")
        and request.url.path.endswith("/callback")
    )
    connect_session_action = request.method == "POST" and (
        request.url.path == "/connect/sessions/inspect"
        or (
            request.url.path.startswith("/connect/")
            and request.url.path.endswith("/start")
        )
    )
    api_key_action = request.headers.get("X-Warden-Key") and request.url.path in {
        "/runs",
        "/tasks",
        "/actions/execute",
        "/mcp/tools/call",
        "/a2a/message:send",
    }
    if (
        not plane.settings.production
        or public_path
        or oauth_callback
        or connect_session_action
        or api_key_action
    ):
        return await call_next(request)
    try:
        principal = await run_in_threadpool(
            authenticator.authenticate, request.headers.get("Authorization")
        )
    except AuthenticationError as exc:
        error = WardenAPIError("unauthorized", str(exc))
        return JSONResponse(
            status_code=401, content=error.body(request.headers.get("X-Request-ID"))
        )
    request.state.principal = principal
    with plane.database.tenant_scope(principal.tenant_id):
        return await call_next(request)


def admin_actor(
    request: Request,
    x_admin_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    try:
        portal_session = getattr(request.state, "portal_session", None)
        if portal_session:
            return portal_session["owner"]
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
    x_warden_key: Annotated[str | None, Header()] = None,
) -> Principal | None:
    if x_warden_key:
        scopes = {"/runs": "runs:create", "/tasks": "tasks:create"}
        required_scope = scopes.get(request.url.path, "actions:execute")
        key = plane.api_keys.authenticate(
            x_warden_key,
            required_scope,
            request.client.host if request.client else None,
        )
        request.state.api_key = key
        return Principal(
            key["agent_id"] or key["key_id"], "default", frozenset({"warden:runtime"})
        )
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


def approval_actor(
    request: Request,
    x_approver_id: Annotated[str | None, Header()] = None,
) -> str:
    if not plane.settings.production:
        if not x_approver_id:
            raise WardenAPIError("unauthorized", "X-Approver-ID is required")
        return x_approver_id
    principal = request.state.principal
    return principal.subject


def guarded(call):
    try:
        return call()
    except WardenAPIError:
        raise
    except (ControlPlaneError, CapabilityError, CredentialError, ValueError) as exc:
        raise classify(str(exc)) from None


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


@app.get("/oauth-result.js", include_in_schema=False)
def oauth_result_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "oauth-result.js", media_type="text/javascript")


@app.get("/product.css", include_in_schema=False)
def product_styles() -> FileResponse:
    return FileResponse(ROOT / "ui" / "product.css", media_type="text/css")


@app.get("/portal", include_in_schema=False)
def test_portal() -> FileResponse:
    return FileResponse(ROOT / "ui" / "portal.html")


@app.get("/portal.js", include_in_schema=False)
def test_portal_script() -> FileResponse:
    return FileResponse(ROOT / "ui" / "portal.js", media_type="text/javascript")


@app.get("/portal.css", include_in_schema=False)
def test_portal_styles() -> FileResponse:
    return FileResponse(ROOT / "ui" / "portal.css", media_type="text/css")


@app.get("/sdk/warden.js", include_in_schema=False)
def browser_sdk() -> FileResponse:
    return FileResponse(ROOT / "ui" / "warden-sdk.js", media_type="text/javascript")


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
def create_owner(
    request: OwnerCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(
        lambda: plane.create_owner(request.owner_id, request.name, request.roles, actor)
    )


@app.get("/owners/agents")
def owner_agents(owner: Annotated[str, Depends(owner_actor)]) -> list[dict]:
    return plane.owner_agents(owner)


@app.post("/owners/agents")
def owner_register_agent(
    request: AgentManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(
            status_code=403, detail="Agent owner must match authenticated owner"
        )
    return guarded(lambda: plane.register_agent(request.model_dump(), owner))


@app.put("/owners/agents/{agent_id}")
def owner_update_agent(
    agent_id: str, request: AgentManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(
            status_code=403, detail="Agent owner must match authenticated owner"
        )
    return guarded(lambda: plane.update_agent(agent_id, request.model_dump(), owner))


@app.post("/owners/connectors")
def owner_register_connector(
    request: ConnectorManifest, owner: Annotated[str, Depends(owner_actor)]
) -> dict:
    if request.owner != owner:
        raise HTTPException(
            status_code=403, detail="Connector owner must match authenticated owner"
        )
    manifest = request.model_dump()
    manifest["status"] = "pending"
    return guarded(lambda: plane.register_connector(manifest, owner))


@app.post("/admin/demo/support-ticket")
def support_demo(request: DemoRun, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(
        lambda: plane.run_support_ticket_scenario(request.principal_id, actor)
    )


@app.post("/admin/agents")
def register_agent(
    request: AgentManifest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(lambda: plane.register_agent(request.model_dump(), actor))


@app.get("/admin/agents")
def agents(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_agents()


@app.post("/admin/agents/{agent_id}/approve")
def approve_agent(agent_id: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.approve_agent(agent_id, actor))


@app.post("/admin/agents/{agent_id}/status")
def agent_status(
    agent_id: str, request: StatusUpdate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(lambda: plane.set_agent_status(agent_id, request.status, actor))


@app.post("/runs")
def create_run(
    request: RunCreate,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    payload = request.model_dump()
    if principal:
        if (
            "warden:admin" not in principal.roles
            and request.agent_id != principal.subject
        ):
            raise HTTPException(
                status_code=403, detail="Runtime identity does not match agent"
            )
        payload["principal_id"] = principal.on_behalf_of or principal.subject
    return guarded(lambda: plane.create_run(**payload))


@app.post("/tasks")
def create_task(
    request: TaskCreate,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    if principal and "warden:admin" not in principal.roles:
        run = plane.database.one(
            "SELECT agent_id FROM runs WHERE run_id=?", (request.run_id,)
        )
        if not run or run["agent_id"] != principal.subject:
            raise HTTPException(
                status_code=403, detail="Runtime identity does not own the run"
            )
    return guarded(lambda: plane.create_task(**request.model_dump()))


@app.post("/admin/capabilities/issue")
def issue_capability(
    request: CapabilityIssue, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    token, claims = guarded(
        lambda: plane.issue_capability(**request.model_dump(), actor=actor)
    )
    return {"capability_token": token, "claims": claims}


@app.post("/capabilities/delegate")
def delegate_capability(
    request: CapabilityDelegate,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    if principal and "warden:admin" not in principal.roles:
        claims = guarded(lambda: plane.capabilities.verify(request.parent_token))
        if claims["agent_id"] != principal.subject:
            raise HTTPException(
                status_code=403,
                detail="Runtime identity does not own the parent capability",
            )
    token, claims = guarded(lambda: plane.delegate_capability(**request.model_dump()))
    return {"capability_token": token, "claims": claims}


@app.post("/admin/capabilities/{jti}/revoke")
def revoke_capability(
    jti: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(lambda: plane.revoke_token(jti, actor, request.reason))
    return {"status": "revoked", "jti": jti}


@app.post("/admin/runs/{run_id}/revoke")
def revoke_run(
    run_id: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(lambda: plane.revoke_run(run_id, actor, request.reason))
    return {"status": "revoked", "run_id": run_id}


@app.post("/admin/keys/rotate")
def rotate_key(actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return {"kid": plane.capabilities.rotate_key(actor), "algorithm": "RS256"}


@app.post("/admin/keys/{kid}/revoke")
def revoke_key(
    kid: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(lambda: plane.capabilities.revoke_key(kid, actor, request.reason))
    return {"kid": kid, "status": "revoked"}


@app.get("/.well-known/warden-keys")
def public_keys() -> list[dict[str, str]]:
    return plane.capabilities.public_keys()


@app.post("/admin/connectors")
def register_connector(
    request: ConnectorManifest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(lambda: plane.register_connector(request.model_dump(), actor))


@app.get("/admin/connectors")
def connectors(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_connectors()


@app.post("/admin/connectors/{connector_id}/status")
def connector_status(
    connector_id: str,
    request: StatusUpdate,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    return guarded(
        lambda: plane.set_connector_status(connector_id, request.status, actor)
    )


@app.post("/admin/policies")
def create_policy(
    request: PolicyCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(
        lambda: plane.seed_policy(
            request.rules, actor, request.policy_id, request.layer, request.target_id
        )
    )


@app.get("/admin/policies")
def policies(_: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.list_policies()


@app.post("/admin/oauth/providers/github")
def configure_github(
    request: OAuthProviderCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    if request.authorization_url and not plane.settings.production:
        contract = PROVIDER_CONTRACTS["github"]
        return guarded(
            lambda: plane.credentials.register_oauth_provider(
                provider_id="github",
                client_id=request.client_id,
                client_secret_alias=request.client_secret_alias,
                authorization_url=request.authorization_url,
                token_url=request.token_url or contract["token_url"],
                api_base_url=request.api_base_url or contract["api_base_url"],
                identity_url=request.identity_url or contract["identity_url"],
                identity_id_field=request.identity_id_field,
                identity_label_field=request.identity_label_field,
                scope_separator=request.scope_separator,
                default_scopes=request.default_scopes,
                owner=actor,
            )
        )
    return guarded(
        lambda: plane.credentials.register_github_provider(
            client_id=request.client_id,
            client_secret_alias=request.client_secret_alias,
            default_scopes=request.default_scopes,
            owner=actor,
        )
    )


@app.post("/admin/oauth/providers/{provider_id}")
def configure_oauth_provider(
    provider_id: str,
    request: OAuthProviderCreate,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    if provider_id != request.provider_id:
        raise HTTPException(status_code=400, detail="Provider ID does not match route")
    contract = PROVIDER_CONTRACTS.get(provider_id, {})
    required = {
        "authorization_url": request.authorization_url
        or contract.get("authorization_url"),
        "token_url": request.token_url or contract.get("token_url"),
        "api_base_url": request.api_base_url or contract.get("api_base_url"),
        "identity_url": request.identity_url or contract.get("identity_url"),
    }
    if not all(required.values()):
        raise HTTPException(
            status_code=400,
            detail="Custom OAuth providers require authorization, token, API base and identity URLs",
        )
    return guarded(
        lambda: plane.credentials.register_oauth_provider(
            provider_id=provider_id,
            client_id=request.client_id,
            client_secret_alias=request.client_secret_alias,
            authorization_url=str(required["authorization_url"]),
            token_url=str(required["token_url"]),
            api_base_url=str(required["api_base_url"]),
            identity_url=str(required["identity_url"]),
            identity_id_field=(
                contract.get("identity_id_field")
                if request.identity_id_field == "id"
                else request.identity_id_field
            )
            or "id",
            identity_label_field=(
                contract.get("identity_label_field")
                if request.identity_label_field == "name"
                else request.identity_label_field
            )
            or "name",
            scope_separator=request.scope_separator,
            default_scopes=request.default_scopes,
            owner=actor,
        )
    )


@app.post("/admin/connections/managed")
def create_managed_connection(
    request: ManagedConnectionCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return guarded(
        lambda: plane.credentials.create_managed_connection(
            **request.model_dump(), actor=actor
        )
    )


@app.post("/admin/connect/sessions")
def mint_connect_session(
    body: ConnectSessionCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    del actor
    return guarded(lambda: plane.connect_sessions.mint(**body.model_dump()))


@app.post("/connect/sessions/inspect")
def inspect_connect_session(body: ConnectSessionToken) -> dict:
    return plane.connect_sessions.inspect(body.session_token)


@app.post("/connect/github/start")
def start_github_connect(body: ConnectSessionToken) -> dict:
    payload = plane.connect_sessions.consume(body.session_token, "github")
    return guarded(
        lambda: plane.credentials.start_github_connect(
            principal_id=payload["sub"],
            agent_id=payload.get("agent_id"),
            label=payload["label"],
            provider_scopes=payload["provider_scopes"],
            grant_scopes=payload["grant_scopes"],
            allowed_methods=payload["allowed_methods"],
            path_patterns=payload["path_patterns"],
            ttl_seconds=None,
            reason=payload["reason"],
        )
    )


@app.post("/connect/{provider_id}/start")
def start_oauth_connect(provider_id: str, body: ConnectSessionToken) -> dict:
    payload = plane.connect_sessions.consume(body.session_token, provider_id)
    return guarded(
        lambda: plane.credentials.start_oauth_connect(
            provider_id=provider_id,
            principal_id=payload["sub"],
            agent_id=payload.get("agent_id"),
            label=payload["label"],
            provider_scopes=payload["provider_scopes"],
            grant_scopes=payload["grant_scopes"],
            allowed_methods=payload["allowed_methods"],
            path_patterns=payload["path_patterns"],
            ttl_seconds=None,
            reason=payload["reason"],
        )
    )


@app.post("/admin/api-keys")
def mint_api_key(
    body: APIKeyCreate, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    return plane.api_keys.mint(**body.model_dump(), actor=actor)


@app.get("/admin/api-keys")
def list_api_keys(
    _: Annotated[str, Depends(admin_actor)], agent_id: str | None = None
) -> list[dict]:
    return plane.api_keys.list(agent_id=agent_id)


@app.post("/admin/api-keys/{key_id}/deprecate")
def deprecate_api_key(key_id: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return plane.api_keys.deprecate(key_id, actor)


@app.post("/admin/api-keys/{key_id}/revoke")
def revoke_api_key(key_id: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return plane.api_keys.revoke(key_id, actor)


@app.post("/admin/apps")
def create_app(body: AppCreate, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return plane.identity.create_app(body.app_id, body.name, actor)


@app.get("/admin/apps")
def list_apps(actor: Annotated[str, Depends(admin_actor)]) -> list[dict]:
    return plane.identity.apps(actor)


@app.get("/admin/apps/{app_id}/identity")
def get_app_identity(app_id: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return plane.identity.identity_config(app_id, actor)


@app.get("/admin/apps/{app_id}/users")
def list_app_users(
    app_id: str, actor: Annotated[str, Depends(admin_actor)]
) -> list[dict]:
    return plane.identity.users(app_id, actor)


@app.post("/admin/apps/{app_id}/identity-provider")
def configure_app_identity_provider(
    app_id: str,
    body: AppIdentityProviderCreate,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    return plane.identity.configure(app_id, body.model_dump(), actor)


@app.post("/apps/{app_id}/identity/resolve")
def resolve_app_identity(app_id: str, body: IdentityResolve) -> dict:
    return plane.identity.resolve(app_id, body.id_token)


@app.post("/apps/{app_id}/identity/webhook")
async def app_identity_webhook(
    app_id: str,
    request: Request,
    x_warden_signature: Annotated[str | None, Header()] = None,
) -> dict:
    return plane.identity.deprovision(app_id, await request.body(), x_warden_signature)


@app.get("/portal/auth/login/{app_id}", include_in_schema=False)
def portal_login(
    app_id: str, redirect: str = "/portal", tenant: str = "default"
) -> RedirectResponse:
    with plane.database.tenant_scope(tenant):
        login = plane.identity.begin_browser_login(app_id, redirect)
    response = RedirectResponse(login["authorization_url"], status_code=302)
    response.set_cookie(
        "warden_oidc_state",
        hashlib.sha256(login["state"].encode()).hexdigest(),
        max_age=600,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/portal/auth/callback",
    )
    return response


@app.get("/portal/auth/callback", include_in_schema=False)
def portal_callback(request: Request, state: str, code: str) -> RedirectResponse:
    tenant = plane.identity.browser_state_tenant(state)
    with plane.database.tenant_scope(tenant):
        result = plane.identity.complete_browser_login(
            state, request.cookies.get("warden_oidc_state"), code
        )
    response = RedirectResponse(result["redirect_path"], status_code=303)
    response.set_cookie(
        "warden_session",
        result["session_token"],
        max_age=8 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        "warden_csrf",
        result["csrf_token"],
        max_age=8 * 60 * 60,
        httponly=False,
        secure=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie("warden_oidc_state", path="/portal/auth/callback")
    return response


@app.get("/portal/session", include_in_schema=False)
def portal_session(request: Request) -> dict:
    session = getattr(request.state, "portal_session", None)
    if not session:
        raise WardenAPIError("unauthorized", "Portal sign-in is required")
    return {
        key: session[key] for key in ("user_id", "app_id", "email", "groups", "owner")
    }


@app.post("/portal/logout", include_in_schema=False)
def portal_logout(request: Request) -> JSONResponse:
    token = request.cookies.get("warden_session")
    if not token:
        raise WardenAPIError("unauthorized", "Portal sign-in is required")
    plane.identity.logout(token)
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie("warden_session", path="/")
    response.delete_cookie("warden_csrf", path="/")
    return response


def _oauth_result(request: Request, result: dict) -> dict | HTMLResponse:
    if "text/html" not in request.headers.get("accept", ""):
        return result
    provider = escape(str(result["connection"]["provider_id"]))
    account = escape(str(result["connection"]["account_identifier"]))
    connection_id = escape(str(result["connection"]["connection_id"]))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Connection complete</title><style>body{{font:16px system-ui;background:#07111f;
    color:#edf5ff;display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:520px;
    padding:32px;border:1px solid #27405d;border-radius:16px;background:#0d1b2d}}a{{color:#64a8ff}}</style>
    </head><body><main><h1>Connection complete</h1><p>{provider} account
    <strong>{account}</strong> is now held by Warden.</p><p>You can close this window or
    <a href="/connections">manage connections</a>.</p></main>
    <script src="/oauth-result.js" data-provider="{provider}" data-account="{account}"
    data-connection="{connection_id}"></script></body></html>"""
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
    request: Request,
    provider_id: str,
    code: str,
    state: str,
) -> dict | HTMLResponse:
    def complete() -> dict:
        tenant = plane.credentials.oauth_state_tenant(state)
        with plane.database.tenant_scope(tenant):
            return plane.credentials.complete_oauth_connect(
                provider_id=provider_id, code=code, state=state
            )

    return _oauth_result(request, guarded(complete))


def _connection_principal(request: Request, principal_id: str | None) -> str:
    portal_session = getattr(request.state, "portal_session", None)
    if portal_session:
        return portal_session["user_id"]
    if plane.settings.production:
        return request.state.principal.subject
    if not principal_id:
        raise HTTPException(status_code=400, detail="principal_id is required locally")
    return principal_id


@app.get("/me/connections")
def my_connections(request: Request, principal_id: str | None = None) -> list[dict]:
    return plane.credentials.connections_for(
        _connection_principal(request, principal_id)
    )


@app.get("/me/grants")
def my_grants(request: Request, principal_id: str | None = None) -> list[dict]:
    return plane.credentials.grants_for(_connection_principal(request, principal_id))


@app.post("/me/grants/{grant_id}/delegate")
def delegate_grant(
    grant_id: str,
    body: GrantDelegate,
    request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    return guarded(
        lambda: plane.credentials.delegate_grant(
            grant_id, body.agent_id, actor, body.reason
        )
    )


@app.post("/me/grants/{grant_id}/revoke")
def revoke_grant(
    grant_id: str,
    body: RevokeRequest,
    request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    guarded(lambda: plane.credentials.revoke_grant(grant_id, actor, body.reason))
    return {"status": "revoked", "grant_id": grant_id}


@app.post("/me/connections/{connection_id}/revoke")
def revoke_connection(
    connection_id: str,
    body: RevokeRequest,
    request: Request,
    principal_id: str | None = None,
) -> dict:
    actor = _connection_principal(request, principal_id)
    guarded(
        lambda: plane.credentials.revoke_connection(connection_id, actor, body.reason)
    )
    return {"status": "revoked", "connection_id": connection_id}


@app.post("/admin/policies/{policy_id}/revoke")
def revoke_policy(
    policy_id: str, request: RevokeRequest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(lambda: plane.revoke_policy(policy_id, actor, request.reason))
    return {"status": "revoked", "policy_id": policy_id}


@app.post("/admin/secrets")
def store_secret(
    request: SecretStore, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(
        lambda: plane.secrets.store(
            request.alias, request.value, actor, request.provider
        )
    )
    return {"status": "stored", "alias": request.alias}


@app.post("/admin/secrets/{alias}/revoke")
def revoke_secret(alias: str, actor: Annotated[str, Depends(admin_actor)]) -> dict:
    guarded(lambda: plane.secrets.revoke(alias, actor))
    return {"status": "revoked", "alias": alias}


@app.get("/admin/approvals")
def approvals(
    _: Annotated[str, Depends(admin_actor)], status: str | None = None
) -> list[dict]:
    return plane.approvals(status)


@app.get("/approvals")
def approver_inbox(
    approver: Annotated[str, Depends(approval_actor)], status: str = "pending"
) -> list[dict]:
    return plane.approvals(status, approver)


@app.get("/approvals/{approval_id}")
def approver_get(
    approval_id: str, approver: Annotated[str, Depends(approval_actor)]
) -> dict:
    return guarded(lambda: plane.approval(approval_id, approver))


@app.post("/approvals/{approval_id}/resolve")
def approver_resolve(
    approval_id: str,
    body: ApprovalResolve,
    approver: Annotated[str, Depends(approval_actor)],
) -> dict:
    guarded(lambda: plane.approval(approval_id, approver))
    return guarded(
        lambda: plane.resolve_approval(
            approval_id, body.approved, approver, body.reason
        )
    )


@app.post("/admin/approvals/{approval_id}/resolve")
def resolve_approval(
    approval_id: str,
    request: ApprovalResolve,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    return guarded(
        lambda: plane.resolve_approval(
            approval_id, request.approved, actor, request.reason
        )
    )


@app.post("/admin/kill-switch")
def kill_switch(
    request: KillSwitchRequest, actor: Annotated[str, Depends(admin_actor)]
) -> dict:
    guarded(lambda: plane.set_kill_switch(request.enabled, actor))
    return {"enabled": request.enabled}


def execute(
    request: ActionRequest,
    principal: Principal | None = None,
    key_id: str | None = None,
) -> dict:
    payload = request.model_dump()
    payload["token"] = payload.pop("capability_token")
    if principal and "warden:admin" not in principal.roles:
        claims = guarded(lambda: plane.capabilities.verify(payload["token"]))
        if claims["agent_id"] != principal.subject:
            raise HTTPException(
                status_code=403, detail="Runtime identity does not own the capability"
            )
    return plane.execute_action(**payload, key_id=key_id)


@app.post("/actions/execute")
def execute_rest(
    http_request: Request,
    request: ActionRequest,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    key = getattr(http_request.state, "api_key", None)
    return execute(request, principal, key["key_id"] if key else None)


@app.post("/mcp/tools/call")
def execute_mcp(
    http_request: Request,
    request: MCPToolCall,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    key = getattr(http_request.state, "api_key", None)
    return {
        "protocol": "mcp",
        "result": execute(request.params, principal, key["key_id"] if key else None),
    }


@app.post("/a2a/message:send")
def execute_a2a(
    http_request: Request,
    request: A2AMessage,
    principal: Annotated[Principal | None, Depends(runtime_principal)],
) -> dict:
    key = getattr(http_request.state, "api_key", None)
    return {
        "protocol": "a2a",
        "result": execute(
            request.action_request, principal, key["key_id"] if key else None
        ),
    }


@app.get("/audit/events")
def audit_events(
    _: Annotated[str, Depends(audit_actor)],
    run_id: str | None = None,
    principal_id: str | None = None,
    agent_id: str | None = None,
    event_type: str | None = None,
    decision: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    limit: int = Query(default=200, ge=1, le=5000),
) -> list[dict]:
    return plane.audit.events(
        run_id=run_id,
        principal_id=principal_id,
        agent_id=agent_id,
        event_type=event_type,
        decision=decision,
        action=action,
        resource=resource,
        limit=limit,
    )


@app.get("/enforcement-traces/{call_id}")
def enforcement_trace(call_id: str, _: Annotated[str, Depends(audit_actor)]) -> dict:
    return plane.enforcement_trace(call_id)


@app.get("/audit/events/page")
def audit_events_page(
    _: Annotated[str, Depends(audit_actor)],
    principal_id: str | None = None,
    agent_id: str | None = None,
    key_id: str | None = None,
    action: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    cursor: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict:
    return plane.audit.page(
        principal_id=principal_id,
        agent_id=agent_id,
        key_id=key_id,
        action=action,
        date_from=date_from,
        date_to=date_to,
        before_sequence=cursor,
        limit=limit,
    )


@app.get("/audit/verify")
def verify_audit(_: Annotated[str, Depends(audit_actor)]) -> dict:
    return plane.audit.verify()


@app.post("/admin/audit/anchor")
def anchor_audit(actor: Annotated[str, Depends(admin_actor)]) -> dict:
    return guarded(lambda: plane.audit.anchor(actor))


@app.post("/admin/maintenance/reconcile")
def reconcile_operations(
    request: ReconcileRequest,
    actor: Annotated[str, Depends(admin_actor)],
) -> dict:
    return guarded(
        lambda: plane.reconcile_stale_operations(actor, request.stale_after_seconds)
    )


@app.get("/audit/export.ndjson")
def export_audit(
    _: Annotated[str, Depends(audit_actor)], run_id: str | None = None
) -> StreamingResponse:
    return StreamingResponse(
        plane.audit.export_ndjson(run_id=run_id),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=warden-audit.ndjson"},
    )


@app.get("/audit/export.csv")
def export_audit_csv(
    _: Annotated[str, Depends(audit_actor)],
    principal_id: str | None = None,
    agent_id: str | None = None,
    key_id: str | None = None,
    action: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> StreamingResponse:
    return StreamingResponse(
        plane.audit.export_csv(
            principal_id=principal_id,
            agent_id=agent_id,
            key_id=key_id,
            action=action,
            date_from=date_from,
            date_to=date_to,
        ),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=warden-audit.csv"},
    )
