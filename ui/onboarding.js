(() => {
  "use strict";
  const $ = (selector) => document.querySelector(selector);
  const state = {};
  if (["127.0.0.1", "localhost"].includes(location.hostname)) {
    $("#auth-mode").value = "admin";
    $("#credential").value = "local-development-admin-key";
  }
  const headers = (admin = false) => {
    const value = $("#credential").value;
    const auth = $("#auth-mode").value === "bearer";
    return {"Content-Type": "application/json", ...(auth && value ? {Authorization: `Bearer ${value}`} : {}), ...(!auth && admin && value ? {"X-Admin-Key": value} : {})};
  };
  const api = async (path, options = {}) => {
    const response = await fetch(path, {...options, headers: {...headers(options.admin), ...(options.headers || {})}});
    const body = await response.json().catch(() => ({detail: `HTTP ${response.status}`}));
    if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
    return body;
  };
  const value = (id) => $(id).value.trim();
  const mark = (step) => document.querySelector(`[data-step="${step}"]`).classList.add("done");
  const log = (label, body) => { $("#output").textContent += `\n\n${label}\n${JSON.stringify(body, null, 2)}`; };
  const post = (path, body, admin = true) => api(path, {method: "POST", admin, body: JSON.stringify(body)});
  $("#reset").onclick = () => { Object.keys(state).forEach((key) => delete state[key]); $("#output").textContent = "Session reset."; document.querySelectorAll(".step").forEach((item) => item.classList.remove("done")); };
  $("#start").onclick = async () => {
    const button = $("#start"); button.disabled = true; $("#output").textContent = "Starting…";
    try {
      const owner = value("#owner-id"), agent = value("#agent-id"), action = value("#action"), resource = value("#resource"), connector = value("#connector-id"), environment = value("#environment");
      try { state.owner = await post("/admin/owners", {owner_id: owner, name: value("#owner-name"), roles: ["agent-owner"]}); log("1. APPLICATION CREATED (owner key shown once)", state.owner); }
      catch (error) { if (!String(error.message).includes("Owner registration failed")) throw error; state.owner = {owner_id: owner, status: "existing"}; log("1. APPLICATION REUSED", state.owner); }
      mark("app");
      const manifest = {agent_id: agent, name: value("#agent-name"), owner, purpose: value("#purpose"), model_provider: "owner-supplied", agent_version: "1.0.0", environment, risk_tier: "medium", allowed_tools: ["cms"], allowed_actions: [action], allowed_data_classifications: ["public"], max_delegation_depth: 0, approved_parents: [], approved_children: []};
      try { state.agent = await post("/admin/agents", manifest); } catch (error) { if (!String(error.message).includes("registration failed")) throw error; state.agent = {agent_id: agent, status: "existing"}; }
      state.agent = await post(`/admin/agents/${encodeURIComponent(agent)}/approve`, {}); log("2. AGENT ACTIVE", state.agent); mark("agent");
      const adapter = value("#adapter"), endpoint = value("#endpoint");
      const connectorBody = {connector_id: connector, tool: "cms", action, adapter_type: adapter, endpoint: adapter === "rest" ? endpoint : null, http_method: "POST", resource_patterns: [resource], required_scopes: [action], owner, risk_tier: "low", rate_limit_per_minute: 10, credential_mode: "bearer", credential_config: adapter === "rest" ? {request_body_mode: "parameters"} : {}, grant_required: true};
      state.connector = await post("/admin/connectors", connectorBody); log("3. PROVIDER CONNECTOR ACTIVE", state.connector); mark("provider");
      state.policy = await post("/admin/policies", {policy_id: `${agent}-starter-policy`, layer: "agent", target_id: agent, rules: {approval_for_production_writes: true, require_grants_for_external: true}});
      log("3A. FAIL-CLOSED STARTER POLICY ACTIVE", state.policy);
      state.connection = await post("/admin/connections/managed", {provider_id: value("#provider-id"), owner_principal_id: "onboarding-user", account_identifier: "onboarding-account", credential: {value: $("#provider-secret").value}, principal_type: "agent", principal_id: agent, label: "first-call", grant_scopes: [action], allowed_methods: ["POST"], path_patterns: ["/*"], ttl_seconds: 3600, reason: "Guided onboarding first protected call"});
      log("4. CREDENTIAL GRANT CREATED", state.connection); mark("grant");
      state.run = await post("/runs", {principal_id: "onboarding-user", agent_id: agent, task: "Execute the onboarding test call", environment}, false);
      state.task = await post("/tasks", {run_id: state.run.run_id, description: "First Warden-protected provider call"}, false);
      state.capability = await post("/admin/capabilities/issue", {run_id: state.run.run_id, scopes: [action], resources: [resource], ttl_seconds: 300});
      state.result = await post("/actions/execute", {capability_token: state.capability.capability_token, runtime_proof: state.run.runtime_proof, request_nonce: crypto.randomUUID(), task_id: state.task.task_id, connector_id: connector, action, resource, parameters: JSON.parse($("#parameters").value), data_classification: "public", environment, grant_id: state.connection.grant.grant_id, risk_signals: {onboarding: true}}, false);
      log("5. FIRST PROTECTED CALL", state.result); mark("call");
    } catch (error) { $("#output").textContent += `\n\nBLOCKED: ${error.message}`; }
    finally { button.disabled = false; }
  };
})();
