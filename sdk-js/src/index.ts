export type Environment = "dev" | "test" | "prod";
export type DataClassification = "public" | "internal" | "sensitive" | "restricted";

export interface WardenClientOptions {
  baseUrl: string;
  accessToken?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

export interface RequestOptions {
  signal?: AbortSignal;
  accessToken?: string;
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
}

export class WardenError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  readonly details: unknown;

  constructor(
    message: string,
    options: { status: number; code?: string; requestId?: string; details?: unknown },
  ) {
    super(message);
    this.name = "WardenError";
    this.status = options.status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.details = options.details;
  }
}

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
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: WardenClientOptions) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.timeoutMs = options.timeoutMs ?? 20_000;
    if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new TypeError("timeoutMs must be a positive finite number");
    }
    this.accessToken = options.accessToken;
    const fetcher = options.fetch ?? globalThis.fetch;
    if (typeof fetcher !== "function") {
      throw new TypeError("A fetch implementation is required");
    }
    this.fetcher = fetcher;
  }

  health(options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("GET", "/health", undefined, options);
  }

  createRun(input: RunCreate, options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("POST", "/runs", input, options);
  }

  createTask(input: TaskCreate, options?: RequestOptions): Promise<Record<string, unknown>> {
    return this.request("POST", "/tasks", input, options);
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
    input: GithubConnectRequest,
    options?: RequestOptions,
  ): Promise<{ provider_id: "github"; connect_url: string; expires_at: string }> {
    return this.request("POST", "/connect/github/start", input, options);
  }

  startOAuthConnect(
    providerId: string,
    input: OAuthConnectRequest,
    options?: RequestOptions,
  ): Promise<{ provider_id: string; connect_url: string; expires_at: string }> {
    return this.request(
      "POST", `/connect/${encodeURIComponent(providerId)}/start`, input, options,
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

  private async request<T>(
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
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
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
        const error = typeof payload === "object" && payload !== null
          ? payload as ErrorBody
          : {};
        const detail = typeof error.detail === "string"
          ? error.detail
          : `Warden request failed with HTTP ${response.status}`;
        throw new WardenError(detail, {
          status: response.status,
          ...(typeof error.code === "string" ? { code: error.code } : {}),
          ...(requestId ? { requestId } : {}),
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
