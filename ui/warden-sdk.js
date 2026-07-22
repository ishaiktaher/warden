export class WardenError extends Error {
    status;
    code;
    requestId;
    details;
    retryable;
    constructor(message, options) {
        super(message);
        this.name = "WardenError";
        this.status = options.status;
        this.code = options.code;
        this.requestId = options.requestId;
        this.details = options.details;
        this.retryable = options.retryable ?? false;
    }
}
export class InvalidRequestError extends WardenError {
}
export class InvalidScopeError extends WardenError {
}
export class InvalidKeyError extends WardenError {
}
export class ExpiredSessionError extends WardenError {
}
export class PolicyDeniedError extends WardenError {
}
export class ApprovalRequiredError extends WardenError {
}
export class RevokedError extends WardenError {
}
export class NotFoundError extends WardenError {
}
export class ConflictError extends WardenError {
}
export class UnauthorizedError extends WardenError {
}
export class ForbiddenError extends WardenError {
}
export class ProviderError extends WardenError {
}
export class UnavailableError extends WardenError {
}
const ERROR_TYPES = {
    invalid_request: InvalidRequestError, invalid_scope: InvalidScopeError,
    invalid_key: InvalidKeyError, expired_session: ExpiredSessionError,
    policy_denied: PolicyDeniedError, approval_required: ApprovalRequiredError,
    revoked: RevokedError, not_found: NotFoundError, conflict: ConflictError,
    unauthorized: UnauthorizedError, forbidden: ForbiddenError,
    provider_error: ProviderError, unavailable: UnavailableError,
};
function normalizeBaseUrl(value) {
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
function nonce() {
    if (globalThis.crypto?.randomUUID) {
        return globalThis.crypto.randomUUID();
    }
    if (!globalThis.crypto?.getRandomValues) {
        throw new Error("A Web Crypto implementation is required");
    }
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0"));
    return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}
export class WardenClient {
    baseUrl;
    timeoutMs;
    accessToken;
    apiKey;
    adminKey;
    csrfToken;
    fetcher;
    constructor(options) {
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
    get app() { return new App(this); }
    get agent() { return new Agent(this); }
    get grant() { return new Grant(this); }
    get key() { return new Key(this); }
    get approval() { return new Approval(this); }
    get auditLog() { return new AuditLog(this); }
    health(options) {
        return this.request("GET", "/health", undefined, options);
    }
    portalSession() {
        return this.request("GET", "/portal/session");
    }
    logout() {
        return this.request("POST", "/portal/logout", {});
    }
    createRun(input, options) {
        return this.request("POST", "/runs", input, options);
    }
    createTask(input, options) {
        return this.request("POST", "/tasks", input, options);
    }
    issueCapability(input) {
        return this.request("POST", "/admin/capabilities/issue", input);
    }
    registerConnector(input) {
        return this.request("POST", "/admin/connectors", input);
    }
    createPolicy(input) {
        return this.request("POST", "/admin/policies", input);
    }
    mintConnectSession(input) {
        return this.request("POST", "/admin/connect/sessions", input);
    }
    async configureOAuthProvider(providerId, input) {
        const { client_secret, ...config } = input;
        if (client_secret)
            await this.request("POST", "/admin/secrets", { alias: input.client_secret_alias, value: client_secret, provider: "local-encrypted" });
        return this.request("POST", `/admin/oauth/providers/${encodeURIComponent(providerId)}`, config);
    }
    enforcementTrace(callId) {
        return this.request("GET", `/enforcement-traces/${encodeURIComponent(callId)}`);
    }
    execute(input, options) {
        return this.request("POST", "/actions/execute", {
            parameters: {},
            data_classification: "internal",
            risk_signals: {},
            ...input,
            request_nonce: input.request_nonce ?? nonce(),
        }, options);
    }
    delegateCapability(input, options) {
        return this.request("POST", "/capabilities/delegate", {
            ttl_seconds: 300,
            ...input,
        }, options);
    }
    startGithubConnect(sessionToken, options) {
        return this.request("POST", "/connect/github/start", { session_token: sessionToken }, options);
    }
    startOAuthConnect(providerId, sessionToken, options) {
        return this.request("POST", `/connect/${encodeURIComponent(providerId)}/start`, { session_token: sessionToken }, options);
    }
    listIntegrations(filters = {}, options) {
        const params = new URLSearchParams();
        if (filters.kind)
            params.set("kind", filters.kind);
        if (filters.query)
            params.set("query", filters.query);
        const query = params.toString();
        return this.request("GET", `/integrations${query ? `?${query}` : ""}`, undefined, options);
    }
    listConnections(principalId, options) {
        return this.request("GET", this.query("/me/connections", principalId), undefined, options);
    }
    listGrants(principalId, options) {
        return this.request("GET", this.query("/me/grants", principalId), undefined, options);
    }
    delegateGrant(grantId, input, principalId, options) {
        const path = this.query(`/me/grants/${encodeURIComponent(grantId)}/delegate`, principalId);
        return this.request("POST", path, input, options);
    }
    revokeGrant(grantId, reason, principalId, options) {
        const path = this.query(`/me/grants/${encodeURIComponent(grantId)}/revoke`, principalId);
        return this.request("POST", path, { reason }, options);
    }
    revokeConnection(connectionId, reason, principalId, options) {
        const path = this.query(`/me/connections/${encodeURIComponent(connectionId)}/revoke`, principalId);
        return this.request("POST", path, { reason }, options);
    }
    query(path, principalId) {
        return principalId
            ? `${path}?principal_id=${encodeURIComponent(principalId)}`
            : path;
    }
    async request(method, path, body, options) {
        const controller = new AbortController();
        const abort = () => controller.abort();
        const callerSignal = options?.signal;
        if (callerSignal?.aborted)
            controller.abort();
        else
            callerSignal?.addEventListener("abort", abort, { once: true });
        const timer = setTimeout(abort, this.timeoutMs);
        const accessToken = options?.accessToken ?? this.accessToken;
        const headers = { Accept: "application/json" };
        for (const [name, value] of Object.entries(options?.headers ?? {}))
            headers[name] = value;
        if (body !== undefined)
            headers["Content-Type"] = "application/json";
        if (accessToken)
            headers.Authorization = `Bearer ${accessToken}`;
        else if (this.apiKey)
            headers["X-Warden-Key"] = this.apiKey;
        else if (this.adminKey)
            headers["X-Admin-Key"] = this.adminKey;
        if (method !== "GET" && method !== "HEAD" && this.csrfToken)
            headers["X-CSRF-Token"] = this.csrfToken;
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
            const payload = contentType.includes("application/json")
                ? await response.json()
                : await response.text();
            if (!response.ok) {
                const outer = typeof payload === "object" && payload !== null
                    ? payload
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
            return payload;
        }
        catch (error) {
            if (error instanceof WardenError)
                throw error;
            if (error instanceof DOMException && error.name === "AbortError") {
                throw new WardenError("Warden request timed out or was cancelled", { status: 0 });
            }
            throw new WardenError("Warden request could not be completed", {
                status: 0,
                details: error instanceof Error ? error.message : String(error),
            });
        }
        finally {
            clearTimeout(timer);
            callerSignal?.removeEventListener("abort", abort);
        }
    }
}
export class App {
    client;
    constructor(client) {
        this.client = client;
    }
    create(appId, name) {
        return this.client.request("POST", "/admin/apps", { app_id: appId, name });
    }
    list() {
        return this.client.request("GET", "/admin/apps");
    }
    identity(appId) {
        return this.client.request("GET", `/admin/apps/${encodeURIComponent(appId)}/identity`);
    }
    users(appId) {
        return this.client.request("GET", `/admin/apps/${encodeURIComponent(appId)}/users`);
    }
    async configureIdentity(appId, input) {
        await this.client.request("POST", "/admin/secrets", { alias: input.client_secret_alias, value: input.client_secret, provider: "local-encrypted" });
        const { client_secret: _, ...config } = input;
        return this.client.request("POST", `/admin/apps/${encodeURIComponent(appId)}/identity-provider`, config);
    }
    async deprovision(appId, externalSubjectId, webhookSecret) {
        const event = { event_id: nonce(), event_type: "user.deprovisioned", external_subject_id: externalSubjectId };
        const bytes = new TextEncoder().encode(JSON.stringify(event));
        const key = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(webhookSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const digest = await globalThis.crypto.subtle.sign("HMAC", key, bytes);
        const signature = [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
        return this.client.request("POST", `/apps/${encodeURIComponent(appId)}/identity/webhook`, event, { headers: { "X-Warden-Signature": `sha256=${signature}` } });
    }
}
export class Agent {
    client;
    constructor(client) {
        this.client = client;
    }
    list() {
        return this.client.request("GET", "/admin/agents");
    }
    create(input) {
        return this.client.request("POST", "/admin/agents", input);
    }
    approve(agentId) {
        return this.client.request("POST", `/admin/agents/${encodeURIComponent(agentId)}/approve`, {});
    }
}
export class Grant {
    client;
    constructor(client) {
        this.client = client;
    }
    list(principalId) {
        const query = principalId ? `?principal_id=${encodeURIComponent(principalId)}` : "";
        return this.client.request("GET", `/me/grants${query}`);
    }
}
export class Key {
    client;
    constructor(client) {
        this.client = client;
    }
    mint(input) {
        return this.client.request("POST", "/admin/api-keys", input);
    }
    list(agentId) {
        return this.client.request("GET", `/admin/api-keys${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : ""}`);
    }
    deprecate(keyId) {
        return this.client.request("POST", `/admin/api-keys/${encodeURIComponent(keyId)}/deprecate`, {});
    }
    revoke(keyId) {
        return this.client.request("POST", `/admin/api-keys/${encodeURIComponent(keyId)}/revoke`, {});
    }
}
export class Approval {
    client;
    constructor(client) {
        this.client = client;
    }
    get(approvalId, approverId) {
        return this.client.request("GET", `/approvals/${encodeURIComponent(approvalId)}`, undefined, { headers: { "X-Approver-ID": approverId } });
    }
    list(approverId, status = "pending") {
        return this.client.request("GET", `/approvals?status=${encodeURIComponent(status)}`, undefined, { headers: { "X-Approver-ID": approverId } });
    }
    resolve(approvalId, approverId, approved, reason = "") {
        return this.client.request("POST", `/approvals/${encodeURIComponent(approvalId)}/resolve`, { approved, reason }, { headers: { "X-Approver-ID": approverId } });
    }
    async await(approvalId, approverId, timeoutMs = 600_000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const result = await this.get(approvalId, approverId);
            if (result.status !== "pending")
                return result;
            await new Promise((resolve) => setTimeout(resolve, Math.min(1_000, deadline - Date.now())));
        }
        throw new ExpiredSessionError("Approval wait timed out", {
            status: 410, code: "expired_session",
        });
    }
}
export class AuditLog {
    client;
    constructor(client) {
        this.client = client;
    }
    page(filters = {}) {
        const query = new URLSearchParams(Object.entries(filters).map(([key, value]) => [key, String(value)])).toString();
        return this.client.request("GET", `/audit/events/page${query ? `?${query}` : ""}`);
    }
    exportCsv(filters = {}) {
        const query = new URLSearchParams(filters).toString();
        return this.client.request("GET", `/audit/export.csv${query ? `?${query}` : ""}`);
    }
}
//# sourceMappingURL=index.js.map