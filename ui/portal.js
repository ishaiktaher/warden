import {WardenClient, WardenError} from "/sdk/warden.js";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const cookie = (name) => document.cookie.split("; ").find((item) => item.startsWith(`${name}=`))?.split("=").slice(1).join("=") || "";
const client = new WardenClient({baseUrl: location.origin, csrfToken: decodeURIComponent(cookie("warden_csrf"))});
const state = {session: null, apps: [], agents: [], keys: [], grants: [], connections: [], keySecrets: new Map(), webhookSecrets: new Map(), paused: null, auditCursor: null, auditFilters: {}};

function show(target, value) { $(target).textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2); }
function values(form) { return Object.fromEntries(new FormData(form).entries()); }
function split(value) { return String(value || "").split(",").map((item) => item.trim()).filter(Boolean); }
function error(target, failure) { show(target, failure instanceof WardenError ? {code: failure.code, detail: failure.message, retryable: failure.retryable} : {detail: String(failure)}); }
function button(label, handler, className = "secondary") { const node = document.createElement("button"); node.type = "button"; node.className = className; node.textContent = label; node.onclick = () => handler().catch((failure) => alert(failure.message)); return node; }
function table(target, columns, rows, actions) {
  const root = $(target); root.replaceChildren(); const tableNode = document.createElement("table");
  const head = document.createElement("tr"); for (const [_, label] of columns) { const th = document.createElement("th"); th.textContent = label; head.append(th); } if (actions) { const th = document.createElement("th"); th.textContent = "Actions"; head.append(th); }
  const thead = document.createElement("thead"); thead.append(head); tableNode.append(thead); const body = document.createElement("tbody");
  for (const row of rows) { const tr = document.createElement("tr"); for (const [key] of columns) { const td = document.createElement("td"); const value = typeof key === "function" ? key(row) : row[key]; td.textContent = Array.isArray(value) ? value.join(", ") : value ?? ""; tr.append(td); } if (actions) { const td = document.createElement("td"); for (const item of actions(row)) td.append(item, " "); tr.append(td); } body.append(tr); }
  tableNode.append(body); root.append(tableNode);
}
function syncSelects() {
  for (const select of $$('[data-apps]')) select.replaceChildren(...state.apps.map((item) => new Option(item.name, item.app_id)));
  for (const select of $$('[data-agents]')) { const blank = select.closest("#connect-form") ? [new Option("No agent delegation", "")] : []; select.replaceChildren(...blank, ...state.agents.map((item) => new Option(`${item.name} (${item.status})`, item.agent_id))); }
  for (const select of $$('[data-keys]')) { const blank = select.closest("#key-form") ? [new Option("None", "")] : []; select.replaceChildren(...blank, ...state.keys.map((item) => new Option(`${item.name} · ${item.key_type} · ${item.status}`, item.key_id))); }
  const grants = $('[data-grants]'); grants.replaceChildren(...state.grants.map((item) => new Option(`${item.label} · ${item.status}`, item.grant_id)));
}

async function loadSession() {
  try { state.session = await client.portalSession(); show("#session-result", state.session); }
  catch (failure) { state.session = null; error("#session-result", failure); }
}
$("#signin-button").onclick = () => { location.href = `/portal/auth/login/${encodeURIComponent($("#login-app").value.trim())}?redirect=/portal&tenant=${encodeURIComponent($("#login-tenant").value.trim())}`; };
$("#logout-button").onclick = async () => { await client.logout(); location.reload(); };
$("#bootstrap-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); const bootstrap = new WardenClient({baseUrl: location.origin, adminKey: input.admin_key}); await bootstrap.app.create(input.app_id, "Warden test portal"); const result = await bootstrap.app.configureIdentity(input.app_id, {issuer: input.issuer, client_id: input.client_id, client_secret: input.client_secret, client_secret_alias: `idp-client-${input.app_id}`, user_id_claim: "sub", email_claim: "email", groups_claim: "groups"}); $("#login-app").value = input.app_id; show("#session-result", {status: "portal_app_ready", app_id: input.app_id, webhook_secret: result.webhook_secret, next: "Sign in with configured OIDC"}); };

async function loadApps() {
  state.apps = await client.app.list(); state.agents = await client.agent.list();
  for (const app of state.apps) { try { app.identity_issuer = (await client.app.identity(app.app_id)).issuer; } catch (failure) { if (failure.code !== "not_found") throw failure; app.identity_issuer = "not configured"; } }
  table("#apps-list", [["app_id", "App"], ["name", "Name"], ["identity_issuer", "OIDC issuer"], ["created_at", "Created"]], state.apps);
  table("#agents-list", [["agent_id", "Agent"], ["name", "Name"], ["status", "Status"], ["allowed_actions", "Actions"]], state.agents);
  const users = []; for (const app of state.apps) { for (const user of await client.app.users(app.app_id)) users.push({...user, app_name: app.name}); }
  table("#users-list", [["app_name", "App"], ["user_id", "Canonical user"], ["email", "Email"], ["groups", "Groups"], ["status", "Status"]], users, (user) => [button("Send signed deprovision", async () => { const secret = state.webhookSecrets.get(user.app_id); if (!secret) throw new Error("Webhook secret is only available immediately after configuration in this portal session"); show("#identity-result", await client.app.deprovision(user.app_id, user.external_subject_id, secret)); await loadApps(); }, "danger")]);
  syncSelects();
}
$("#refresh-apps").onclick = () => loadApps().catch((failure) => error("#identity-result", failure));
$("#app-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); show("#identity-result", await client.app.create(input.app_id, input.name)); await loadApps(); };
$("#identity-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); const {app_id, ...config} = input; const alias = `idp-client-${app_id}`; const result = await client.app.configureIdentity(app_id, {...config, client_secret_alias: alias}); state.webhookSecrets.set(app_id, result.webhook_secret); show("#identity-result", {...result, webhook_secret: "shown once and retained only in this page"}); await loadApps(); };

async function loadProviders() {
  const exact = new Set(["github", "google", "slack", "notion", "stripe"]); const integrations = (await client.listIntegrations({kind: "oauth2"})).filter((item) => exact.has(item.integration_id.replace("oauth:", "")));
  const root = $("#providers"); root.replaceChildren(); for (const item of integrations) { const node = document.createElement("span"); node.className = "provider"; node.textContent = `${item.name}: ${item.verification}`; root.append(node); }
  $("#provider-select").replaceChildren(...integrations.map((item) => new Option(`${item.name} · ${item.verification}`, item.integration_id.replace("oauth:", ""))));
}
async function ensureSyntheticGithub() {
  if (!location.pathname.startsWith("/portal")) return;
  await client.configureOAuthProvider("github", {provider_id: "github", client_id: "synthetic-client", client_secret: "synthetic-secret", client_secret_alias: "portal-github-client", authorization_url: `${location.origin}/_dev/mock/github/authorize`, token_url: `${location.origin}/_dev/mock/github/token`, api_base_url: `${location.origin}/_dev/mock/github`, identity_url: `${location.origin}/_dev/mock/github/user`, identity_id_field: "id", identity_label_field: "login", scope_separator: " ", default_scopes: ["repo"]});
}
async function loadWallet() {
  state.connections = await client.listConnections(); state.grants = await client.listGrants();
  table("#connections-list", [["provider_id", "Provider"], ["account_identifier", "Account"], ["status", "Status"]], state.connections, (item) => [button("Revoke", async () => { await client.revokeConnection(item.connection_id, "Portal test revoke"); await loadWallet(); }, "danger")]);
  table("#grants-list", [["label", "Grant"], ["scopes", "Scopes"], ["status", "Status"]], state.grants, (item) => [button("Revoke", async () => { await client.revokeGrant(item.grant_id, "Portal test revoke"); await loadWallet(); }, "danger")]); syncSelects();
}
$("#connect-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); if (input.provider_id === "github") await ensureSyntheticGithub(); const session = await client.mintConnectSession({principal_id: state.session.user_id, agent_id: input.agent_id || null, allowed_providers: [input.provider_id], provider_scopes: split(input.provider_scopes), grant_scopes: split(input.grant_scopes), allowed_methods: ["POST"], path_patterns: [input.path], reason: "Portal connection test", label: "portal"}); const widget = $("#connect-widget"); widget.setAttribute("session-token", session.session_token); await widget.load(); show("#connect-result", {status: "session_ready", expires_at: session.expires_at}); };
$("#connect-widget").addEventListener("warden-event", async (event) => { show("#connect-result", event.detail); if (event.detail.type === "success") await loadWallet(); });

async function loadKeys() {
  state.keys = await client.key.list(); table("#keys-list", [["name", "Name"], ["key_type", "Type"], ["key_prefix", "Prefix"], ["scopes", "Scopes"], ["expires_at", "Expiry"], ["cidr_allowlist", "CIDRs"], ["status", "State"], ["last_used_at", "Last used"]], state.keys, (item) => [button("Deprecate", async () => { await client.key.deprecate(item.key_id); await loadKeys(); }), button("Revoke cascade", async () => { await client.key.revoke(item.key_id); await loadKeys(); }, "danger")]); syncSelects();
}
$("#agent-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); const owner = state.session.owner || "control-plane-admin"; await client.agent.create({agent_id: input.agent_id, name: input.name, owner, purpose: "Portal gateway test", model_provider: "test", agent_version: "1", environment: "test", risk_tier: "low", allowed_tools: ["github"], allowed_actions: [input.action], allowed_data_classifications: ["internal"], max_delegation_depth: 0, approved_parents: [], approved_children: []}); await client.agent.approve(input.agent_id); await loadApps(); };
$("#key-form").onsubmit = async (event) => { event.preventDefault(); const input = values(event.currentTarget); const minted = await client.key.mint({key_type: input.key_type, name: `${input.agent_id}-${input.key_type}`, scopes: split(input.scopes), agent_id: input.agent_id || null, expires_in: Number(input.expires_in), cidr_allowlist: split(input.cidrs), parent_key_id: input.parent_key_id || null}); state.keySecrets.set(minted.key_id, minted.api_key); show("#key-secret", {key_id: minted.key_id, api_key: minted.api_key, warning: "This plaintext is not returned again"}); await loadKeys(); };

async function renderTrace(callId) { const trace = await client.enforcementTrace(callId); const list = $("#trace-list"); list.replaceChildren(); for (const stage of trace.stages) { const item = document.createElement("li"); item.className = stage.status; item.textContent = `${stage.stage}: ${stage.status} — ${JSON.stringify(stage.detail)}`; list.append(item); } }
async function runGateway(approvalId = null) {
  const input = approvalId ? state.paused.input : values($("#gateway-form")); const rawKey = state.keySecrets.get(input.key_id); if (!rawKey) throw new Error("The selected key plaintext is no longer available; mint a new key in this page session");
  const keyClient = new WardenClient({baseUrl: location.origin, apiKey: rawKey, csrfToken: decodeURIComponent(cookie("warden_csrf"))});
  let payload;
  if (approvalId) payload = {...state.paused.payload, approval_id: approvalId};
  else {
    try { await client.registerConnector({connector_id: "portal-github", tool: "github", action: input.action, adapter_type: "local_emulator", endpoint: "https://api.github.com/repos/acme/app/issues", http_method: "POST", resource_patterns: ["github://repos/acme/*"], required_scopes: [input.action], owner: state.session.owner || "control-plane-admin", risk_tier: "high", grant_required: true}); } catch (failure) { if (failure.code !== "conflict") throw failure; }
    await client.createPolicy({policy_id: "portal-default", layer: "platform", target_id: "*", rules: {}});
    const run = await client.createRun({principal_id: state.session.user_id, agent_id: input.agent_id, task: "Portal gateway call", environment: "test"}); const task = await client.createTask({run_id: run.run_id, description: "Portal gateway call"}); const capability = await client.issueCapability({run_id: run.run_id, scopes: [input.action], resources: [input.resource], ttl_seconds: 300});
    payload = {capability_token: capability.capability_token, runtime_proof: run.runtime_proof, task_id: task.task_id, connector_id: "portal-github", action: input.action, resource: input.resource, parameters: JSON.parse(input.parameters), environment: "test", grant_id: input.grant_id};
  }
  const result = await keyClient.execute(payload); show("#gateway-result", result); await renderTrace(result.tool_call_id);
  if (result.status === "approval_required") { state.paused = {input, result, payload}; $("#gateway-state").className = "notice"; $("#gateway-state").textContent = `Waiting for approval ${result.approval_id}. Continue in the approval inbox below.`; location.hash = "approvals"; await loadApprovals(); } else { state.paused = null; $("#gateway-state").textContent = "Call completed."; }
  await loadKeys();
}
$("#gateway-form").onsubmit = (event) => { event.preventDefault(); runGateway().catch((failure) => error("#gateway-result", failure)); };

async function loadApprovals() {
  if (!state.session) return; const approvals = await client.approval.list(state.session.user_id); table("#approval-list", [["action", "Action"], ["resource", "Resource"], ["requested_at", "Requested"]], approvals, (item) => [button("Approve & resume", async () => { await client.approval.resolve(item.approval_id, state.session.user_id, true, "Approved in test portal"); if (state.paused?.result.approval_id === item.approval_id) await runGateway(item.approval_id); await loadApprovals(); }), button("Deny", async () => { await client.approval.resolve(item.approval_id, state.session.user_id, false, "Denied in test portal"); await loadApprovals(); }, "danger")]);
}
$("#refresh-approvals").onclick = () => loadApprovals().catch((failure) => alert(failure.message));

async function loadAudit(reset = false) { if (reset) state.auditCursor = null; const page = await client.auditLog.page({...state.auditFilters, ...(state.auditCursor ? {cursor: state.auditCursor} : {}), limit: 50}); state.auditCursor = page.next_cursor; table("#audit-list", [["sequence", "#"], ["timestamp", "Time"], ["event_type", "Event"], ["principal_id", "Principal"], ["agent_id", "Agent"], ["key_id", "Key"], ["decision", "Decision"]], page.items); }
$("#audit-form").onsubmit = async (event) => { event.preventDefault(); state.auditFilters = Object.fromEntries(Object.entries(values(event.currentTarget)).filter(([, value]) => value)); await loadAudit(true); };
$("#audit-next").onclick = () => loadAudit().catch((failure) => alert(failure.message));
$("#audit-csv").onclick = async () => { const csv = await client.auditLog.exportCsv(state.auditFilters); const link = document.createElement("a"); link.href = URL.createObjectURL(new Blob([csv], {type: "text/csv"})); link.download = "warden-audit.csv"; link.click(); URL.revokeObjectURL(link.href); };

async function start() { await loadSession(); await loadProviders(); if (!state.session) return; await Promise.all([loadApps(), loadWallet(), loadKeys(), loadApprovals(), loadAudit(true)]); }
start().catch((failure) => show("#session-result", {fatal: failure.message}));
