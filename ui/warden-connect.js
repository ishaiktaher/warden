(() => {
  "use strict";
  class WardenConnect extends HTMLElement {
    constructor() {
      super(); this.attachShadow({mode: "open"}); this.getAccessToken = async () => null;
    }
    connectedCallback() { this.render(); this.load().catch((error) => this.message(error.message, true)); }
    async headers() { const token = await this.getAccessToken(); return {"Content-Type": "application/json", ...(token ? {Authorization: `Bearer ${token}`} : {})}; }
    message(value, failed = false) { const node = this.shadowRoot.querySelector("[data-message]"); node.textContent = value; node.dataset.failed = String(failed); }
    render() {
      this.shadowRoot.innerHTML = `<style>:host{display:block;font:14px system-ui;color:#edf5ff}.box{border:1px solid #27405d;border-radius:14px;padding:16px;background:#0d1b2d}label{display:block;color:#91a7bf;font-size:12px;margin:9px 0 4px}select,input{width:100%;box-sizing:border-box;background:#071524;color:#edf5ff;border:1px solid #27405d;border-radius:8px;padding:9px}button{margin-top:12px;border:0;border-radius:8px;background:#64a8ff;color:#06111e;font-weight:800;padding:10px 13px;cursor:pointer}[data-message]{color:#91a7bf;margin-top:9px}[data-failed=true]{color:#ff667d}</style><div class="box"><strong>Connect a provider</strong><label>Provider</label><select data-provider><option>Loading…</option></select><label>Agent ID</label><input data-agent><label>Warden scopes (comma-separated)</label><input data-scopes><button data-connect>Authorize connection</button><div data-message>Choose a provider to continue.</div></div>`;
      this.shadowRoot.querySelector("[data-agent]").value = this.getAttribute("agent-id") || "";
      this.shadowRoot.querySelector("[data-scopes]").value = this.getAttribute("grant-scopes") || "data.read";
      this.shadowRoot.querySelector("[data-connect]").onclick = () => this.connect().catch((error) => this.message(error.message, true));
    }
    async load() { const response = await fetch(`${this.getAttribute("base-url") || ""}/integrations?kind=oauth2`); const items = await response.json(); if (!response.ok) throw new Error(items.detail || "Provider catalog unavailable"); const select = this.shadowRoot.querySelector("[data-provider]"); select.replaceChildren(...items.map((item) => { const option = document.createElement("option"); option.value = item.integration_id.split(":")[1]; option.textContent = item.name; return option; })); }
    async connect() {
      const base = this.getAttribute("base-url") || "", provider = this.shadowRoot.querySelector("[data-provider]").value, principal = this.getAttribute("principal-id") || "user", agent = this.shadowRoot.querySelector("[data-agent]").value.trim() || null, scopes = this.shadowRoot.querySelector("[data-scopes]").value.split(",").map((item) => item.trim()).filter(Boolean);
      const before = await this.connections(base, principal); const response = await fetch(`${base}/connect/${encodeURIComponent(provider)}/start`, {method: "POST", headers: await this.headers(), body: JSON.stringify({principal_id: principal, agent_id: agent, label: `${provider}-default`, provider_scopes: [], grant_scopes: scopes, allowed_methods: [], path_patterns: ["/*"], ttl_seconds: 86400, reason: "User-authorized embedded connection"})}); const body = await response.json(); if (!response.ok) throw new Error(body.detail || "Connection could not start");
      const popup = window.open(body.connect_url, "warden-connect", "popup,width=620,height=760"); if (!popup) throw new Error("Allow popups to complete OAuth authorization"); this.message("Waiting for provider authorization…");
      const deadline = Date.now() + 10 * 60 * 1000; while (Date.now() < deadline && !popup.closed) { await new Promise((resolve) => setTimeout(resolve, 1200)); const current = await this.connections(base, principal); const connected = current.find((item) => !before.some((old) => old.connection_id === item.connection_id)); if (connected) { popup.close(); this.message(`${connected.provider_id} connected as ${connected.account_identifier}`); this.dispatchEvent(new CustomEvent("warden-connected", {detail: connected, bubbles: true})); return; } } this.message("Authorization window closed or expired.", true);
    }
    async connections(base, principal) { const response = await fetch(`${base}/me/connections?principal_id=${encodeURIComponent(principal)}`, {headers: await this.headers()}); const body = await response.json(); if (!response.ok) throw new Error(body.detail || "Connections unavailable"); return body; }
  }
  if (!customElements.get("warden-connect")) customElements.define("warden-connect", WardenConnect);
})();
