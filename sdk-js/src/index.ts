export type Environment = "dev" | "test" | "prod";
export type DataClassification = "public" | "internal" | "sensitive" | "restricted";

export interface WardenClientOptions {
  baseUrl: string;
  accessToken?: string;
  apiKey?: string;
  adminKey?: string;
  csrfToken?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

export interface RequestOptions {
  signal?: AbortSignal;
  accessToken?: string;
  headers?: Readonly<Record<string, string>>;
}

export interface RunCreate {
  principal_id: string;
  agent_id: string;
  task: string;
  environment: Environment;
  parent_run_id?: string | null;
}

export interface TaskCreate {
  run_id: string;
  description: string;
  parent_task_id?: string | null;
}

export interface ActionRequest {
  capability_token: string;
  runtime_proof: string;
  task_id: string;
  connector_id: string;
  action: string;
  resource: string;
  environment: Environment;
  parameters?: Record<string, unknown>;
  data_classification?: DataClassification;
  approval_id?: string | null;
  grant_id?: string | null;
  risk_signals?: Record<string, unknown>;
  request_nonce?: string;
}

export interface ActionResult {
  status: "executed" | "denied" | "error" | "approval_required";
  tool_call_id: string;
  reason?: string;
  approval_id?: string;
  result?: Record<string, unknown>;
}

export interface OAuthConnectRequest {
  principal_id: string;
  agent_id?: string | null;
  label?: string;
  provider_scopes?: string[];
  grant_scopes: string[];
  allowed_methods?: string[];
  path_patterns?: string[];
  ttl_seconds?: number | null;
  reason: string;
}

export type GithubConnectRequest = OAuthConnectRequest;

export interface Integration {
  integration_id: string;
  name: string;
  kind: "oauth2" | "managed_secret";
  setup_mode: "oauth_provider_configuration" | "managed_secret_template";
  docs_url: string;
  credential_modes: string[];
  status: "supported";
}

export interface CredentialConnection {
  connection_id: string;
  provider_id: string;
  owner_principal_id: string;
  account_identifier: string;
  credential_kind: string;
  granted_scopes: string[];
  status: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  last_used_at?: string | null;
}

export interface CredentialGrant {
  grant_id: string;
  connection_id: string;
  principal_type: string;
  principal_id: string;
  label: string;
  scopes: string[];
  allowed_methods: string[];
  path_patterns: string[];
  expires_at?: string | null;
  status: string;
  reason: string;
}

export interface DelegateCapabilityRequest {
  parent_token: string;
  parent_runtime_proof: string;
  child_run_id: string;
  scopes: string[];
  resources: string[];
  ttl_seconds?: number;
}

interface ErrorBody {
  detail?: unknown;
  code?: unknown;
  retryable?: unknown;
  request_id?: unknown;
  error?: ErrorBody;
}

export class WardenError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  readonly details: unknown;
  readonly retryable: boolean;

  constructor(
    message: string,
    options: { status: number; code?: string; requestId?: string; details?: unknown; retryable?: boolean },
  ) {
    super(message);
    this.name = "WardenError";
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.details = options.details;
    this.retryable = options.retryable ?? false;
  }
}

export class InvalidRequestError extends WardenError {}
export class InvalidScopeError extends WardenError {}
export class InvalidKeyError extends WardenError {}
export class ExpiredSessionError extends WardenError {}
export class PolicyDeniedError extends WardenError {}
export class ApprovalRequiredError extends WardenError {}
export class RevokedError extends WardenError {}
export class NotFoundError extends WardenError {}
export class ConflictError extends WardenError {}
export class UnauthorizedError extends WardenError {}
export class ForbiddenError extends WardenError {}
export class ProviderError extends WardenError {}
export class UnavailableError extends WardenError {}

const ERROR_TYPES: Record<string, typeof WardenError> = {
  invalid_request: InvalidRequestError, invalid_scope: InvalidScopeError,
  invalid_key: InvalidKeyError, expired_session: ExpiredSessionError,
  policy_denied: PolicyDeniedError, approval_required: ApprovalRequiredError,
  revoked: RevokedError, not_found: NotFoundError, conflict: ConflictError,
  unauthorized: UnauthorizedError, forbidden: ForbiddenError,
  provider_error: ProviderError, unavailable: UnavailableError,
};

function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new TypeError("Warden baseUrl must use HTTPS except on localhost");
  }
  url.pathname = url.pathname.replace(/\/$/, "");
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function nonce(): string {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("A Web Crypto implementation is required");
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

export class WardenClient {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  private readonly accessToken: string | undefined;
  private readonly apiKey: string | undefined;
  private readonly adminKey: string | undefined;
  private readonly csrfToken: string | undefined;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: WardenClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.timeoutMs = options.timeoutMs ?? 20_000;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive finite number");
    }
    this.accessToken = options.accessToken;
    this.apiKey = options.apiKey;
    this.adminKey = options.adminKey;
    this.csrfToken = options.csrfToken;
    const fetcher = options.fetch ?? globalThis.fetch;
    if (typeof fetcher !== "function") {
      throw new TypeError("A fetch implementation is required");
    }
    this.fetcher = fetcher;
  }

  get app(): App { return new App(this); }
  get agent(): Agent { return new Agent(this); }
  get grant(): Grant { return new Grant(this); }
  get key(): Key { return new Key(this); }
  get approval(): Approval { return new Approval(this); }
  get auditLog(): AuditLog { return new AuditLog(this); }

  health(options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("GET", "/health", undefined, options);
  }

  portalSession(): Promise<Record<string, unknown>> {
    return this.request("GET", "/portal/session");
  }

  logout(): Promise<Record<string, unknown>> {
    return this.request("POST", "/portal/logout", {});
  }

  createRun(input: RunCreate, options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("POST", "/runs", input, options);
  }

  createTask(input: TaskCreate, options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("POST", "/tasks", input, options);
  }

  issueCapability(input: { run_id: string; scopes: string[]; resources: string[]; ttl_seconds?: number }): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/capabilities/issue", input);
  }

  registerConnector(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/connectors", input);
  }

  createPolicy(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/policies", input);
  }

  mintConnectSession(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request("POST", "/admin/connect/sessions", input);
  }

  async configureOAuthProvider(providerId: string, input: Record<string, unknown> & { client_secret?: string; client_secret_alias: string }): Promise<Record<string, unknown>> {
    const { client_secret, ...config } = input;
    if (client_secret) await this.request("POST", "/admin/secrets", { alias: input.client_secret_alias, value: client_secret, provider: "local-encrypted" });
    return this.request("POST", `/admin/oauth/providers/${encodeURIComponent(providerId)}`, config);
  }

  enforcementTrace(callId: string): Promise<Record<string, unknown>> {
    return this.request("GET", `/enforcement-traces/${encodeURIComponent(callId)}`);
  }

  execute(input: ActionRequest, options?: RequestOptions): Promise<ActionResult> {
    return this.request("POST", "/actions/execute", {
      parameters: {},
      data_classification: "internal",
      risk_signals: {},
      ...input,
      request_nonce: input.request_nonce ?? nonce(),
    }, options);
  }

  delegateCapability(
    input: DelegateCapabilityRequest,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    return this.request("POST", "/capabilities/delegate", {
      ttl_seconds: 300,
      ...input,
    }, options);
  }

  startGithubConnect(
    sessionToken: string,
    options?: RequestOptions,
  ): Promise<{ provider_id: "github"; connect_url: string; expires_at: string }> {
    return this.request("POST", "/connect/github/start", { session_token: sessionToken }, options);
  }

  startOAuthConnect(
    providerId: string,
    sessionToken: string,
    options?: RequestOptions,
  ): Promise<{ provider_id: string; connect_url: string; expires_at: string }> {
    return this.request(
      "POST", `/connect/${encodeURIComponent(providerId)}/start`, { session_token: sessionToken }, options,
    );
  }

  listIntegrations(
    filters: { kind?: "oauth2" | "managed_secret"; query?: string } = {},
    options?: RequestOptions,
  ): Promise<Integration[]> {
    const params = new URLSearchParams();
    if (filters.kind) params.set("kind", filters.kind);
    if (filters.query) params.set("query", filters.query);
    const query = params.toString();
    return this.request("GET", `/integrations${query ? `?${query}` : ""}`, undefined, options);
  }

  listConnections(
    principalId?: string,
    options?: RequestOptions,
  ): Promise<CredentialConnection[]> {
    return this.request("GET", this.query("/me/connections", principalId), undefined, options);
  }

  listGrants(
    principalId?: string,
    options?: RequestOptions,
  ): Promise<CredentialGrant[]> {
    return this.request("GET", this.query("/me/grants", principalId), undefined, options);
  }

  delegateGrant(
    grantId: string,
    input: { agent_id: string; reason: string },
    principalId?: string,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    const path = this.query(`/me/grants/${encodeURIComponent(grantId)}/delegate`, principalId);
    return this.request("POST", path, input, options);
  }

  revokeGrant(
    grantId: string,
    reason: string,
    principalId?: string,
    options?: RequestOptions,
  ): Promise<{ status: "revoked"; grant_id: string }> {
    const path = this.query(`/me/grants/${encodeURIComponent(grantId)}/revoke`, principalId);
    return this.request("POST", path, { reason }, options);
  }

  revokeConnection(
    connectionId: string,
    reason: string,
    principalId?: string,
    options?: RequestOptions,
  ): Promise<{ status: "revoked"; connection_id: string }> {
    const path = this.query(
      `/me/connections/${encodeURIComponent(connectionId)}/revoke`, principalId,
    );
    return this.request("POST", path, { reason }, options);
  }

  private query(path: string, principalId?: string): string {
    return principalId
      ? `${path}?principal_id=${encodeURIComponent(principalId)}`
      : path;
  }

  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: RequestOptions,
  ): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    const callerSignal = options?.signal;
    if (callerSignal?.aborted) controller.abort();
    else callerSignal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, this.timeoutMs);
    const accessToken = options?.accessToken ?? this.accessToken;
    const headers: Record<string, string> = { Accept: "application/json" };
    for (const [name, value] of Object.entries(options?.headers ?? {})) headers[name] = value;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    else if (this.apiKey) headers["X-Warden-Key"] = this.apiKey;
    else if (this.adminKey) headers["X-Admin-Key"] = this.adminKey;
    if (method !== "GET" && method !== "HEAD" && this.csrfToken) headers["X-CSRF-Token"] = this.csrfToken;
    try {
      const response = await this.fetcher(`${this.baseUrl}${path}`, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
        redirect: "error",
      });
      const requestId = response.headers.get("x-request-id") ?? undefined;
      const contentType = response.headers.get("content-type") ?? "";
      const payload: unknown = contentType.includes("application/json")
        ? await response.json()
        : await response.text();
      if (!response.ok) {
        const outer = typeof payload === "object" && payload !== null
          ? payload as ErrorBody
          : {};
        const error = outer.error ?? outer;
        const detail = typeof error.detail === "string"
          ? error.detail
          : `Warden request failed with HTTP ${response.status}`;
        const code = typeof error.code === "string" ? error.code : undefined;
        const ErrorType = code ? (ERROR_TYPES[code] ?? WardenError) : WardenError;
        throw new ErrorType(detail, {
          status: response.status,
          ...(code ? { code } : {}),
          ...(typeof error.request_id === "string" ? { requestId: error.request_id } : requestId ? { requestId } : {}),
          retryable: error.retryable === true,
          details: payload,
        });
      }
      return payload as T;
    } catch (error) {
      if (error instanceof WardenError) throw error;
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new WardenError("Warden request timed out or was cancelled", { status: 0 });
      }
      throw new WardenError("Warden request could not be completed", {
        status: 0,
        details: error instanceof Error ? error.message : String(error),
      });
    } finally {
      clearTimeout(timer);
      callerSignal?.removeEventListener("abort", abort);
    }
  }
}

export class App {
  constructor(private readonly client: WardenClient) {}
  create(appId: string, name: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/admin/apps", { app_id: appId, name });
  }
  list(): Promise<ReadonlyArray<Record<string, unknown>>> {
    return this.client.request("GET", "/admin/apps");
  }
  identity(appId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/admin/apps/${encodeURIComponent(appId)}/identity`);
  }
  users(appId: string): Promise<ReadonlyArray<Record<string, unknown>>> {
    return this.client.request("GET", `/admin/apps/${encodeURIComponent(appId)}/users`);
  }
  async configureIdentity(appId: string, input: Record<string, unknown> & { client_secret: string; client_secret_alias: string }): Promise<Record<string, unknown>> {
    await this.client.request("POST", "/admin/secrets", { alias: input.client_secret_alias, value: input.client_secret, provider: "local-encrypted" });
    const { client_secret: _, ...config } = input;
    return this.client.request("POST", `/admin/apps/${encodeURIComponent(appId)}/identity-provider`, config);
  }
  async deprovision(appId: string, externalSubjectId: string, webhookSecret: string): Promise<Record<string, unknown>> {
    const event = { event_id: nonce(), event_type: "user.deprovisioned", external_subject_id: externalSubjectId };
    const bytes = new TextEncoder().encode(JSON.stringify(event));
    const key = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(webhookSecret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const digest = await globalThis.crypto.subtle.sign("HMAC", key, bytes);
    const signature = [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
    return this.client.request("POST", `/apps/${encodeURIComponent(appId)}/identity/webhook`, event,
      { headers: { "X-Warden-Signature": `sha256=${signature}` } });
  }
}

export class Agent {
  constructor(private readonly client: WardenClient) {}
  list(): Promise<ReadonlyArray<Record<string, unknown>>> {
    return this.client.request("GET", "/admin/agents");
  }
  create(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/admin/agents", input);
  }
  approve(agentId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/admin/agents/${encodeURIComponent(agentId)}/approve`, {});
  }
}

export class Grant {
  constructor(private readonly client: WardenClient) {}
  list(principalId?: string): Promise<CredentialGrant[]> {
    const query = principalId ? `?principal_id=${encodeURIComponent(principalId)}` : "";
    return this.client.request("GET", `/me/grants${query}`);
  }
}

export class Key {
  constructor(private readonly client: WardenClient) {}
  mint(input: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.client.request("POST", "/admin/api-keys", input);
  }
  list(agentId?: string): Promise<ReadonlyArray<Record<string, unknown>>> {
    return this.client.request("GET", `/admin/api-keys${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ""}`);
  }
  deprecate(keyId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/admin/api-keys/${encodeURIComponent(keyId)}/deprecate`, {});
  }
  revoke(keyId: string): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/admin/api-keys/${encodeURIComponent(keyId)}/revoke`, {});
  }
}

export class Approval {
  constructor(private readonly client: WardenClient) {}
  get(approvalId: string, approverId: string): Promise<Record<string, unknown>> {
    return this.client.request("GET", `/approvals/${encodeURIComponent(approvalId)}`, undefined,
      { headers: { "X-Approver-ID": approverId } });
  }
  list(approverId: string, status = "pending"): Promise<ReadonlyArray<Record<string, unknown>>> {
    return this.client.request("GET", `/approvals?status=${encodeURIComponent(status)}`, undefined,
      { headers: { "X-Approver-ID": approverId } });
  }
  resolve(approvalId: string, approverId: string, approved: boolean, reason = ""): Promise<Record<string, unknown>> {
    return this.client.request("POST", `/approvals/${encodeURIComponent(approvalId)}/resolve`, { approved, reason },
      { headers: { "X-Approver-ID": approverId } });
  }
  async await(approvalId: string, approverId: string, timeoutMs = 600_000): Promise<Record<string, unknown>> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const result = await this.get(approvalId, approverId);
      if (result.status !== "pending") return result;
      await new Promise((resolve) => setTimeout(resolve, Math.min(1_000, deadline - Date.now())));
    }
    throw new ExpiredSessionError("Approval wait timed out", {
      status: 410, code: "expired_session",
    });
  }
}

export class AuditLog {
  constructor(private readonly client: WardenClient) {}
  page(filters: Readonly<Record<string, string | number>> = {}): Promise<Record<string, unknown>> {
    const query = new URLSearchParams(Object.entries(filters).map(([key, value]) => [key, String(value)])).toString();
    return this.client.request("GET", `/audit/events/page${query ? `?${query}` : ""}`);
  }
  exportCsv(filters: Readonly<Record<string, string>> = {}): Promise<string> {
    const query = new URLSearchParams(filters).toString();
    return this.client.request("GET", `/audit/export.csv${query ? `?${query}` : ""}`);
  }
}
