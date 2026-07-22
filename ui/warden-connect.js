(() => {
  "use strict";

  class WardenConnect extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({mode: "open"});
      this.onSuccess = null;
      this.onError = null;
    }

    connectedCallback() {
      this.render();
      this.load().catch((error) => this.fail("session_invalid", error.message));
    }

    get sessionToken() { return this.getAttribute("session-token") || ""; }
    get baseUrl() { return this.getAttribute("base-url") || ""; }

    event(type, code, detail) {
      const payload = {type, code, detail};
      this.dispatchEvent(new CustomEvent("warden-event", {detail: payload, bubbles: true}));
      return payload;
    }

    fail(code, detail) {
      this.message(detail, true);
      const payload = this.event("error", code, detail);
      if (typeof this.onError === "function") this.onError(payload);
    }

    succeed(detail) {
      this.message(`${detail.provider_id} connected as ${detail.account_identifier}`);
      const payload = this.event("success", "connected", detail);
      if (typeof this.onSuccess === "function") this.onSuccess(payload);
    }

    message(value, failed = false) {
      const node = this.shadowRoot.querySelector("[data-message]");
      node.textContent = value; node.dataset.failed = String(failed);
    }

    render() {
      this.shadowRoot.innerHTML = `<style>:host{display:block;font:14px system-ui;color:#edf5ff}.box{border:1px solid #27405d;border-radius:14px;padding:16px;background:#0d1b2d}label{display:block;color:#91a7bf;font-size:12px;margin:9px 0 4px}select{width:100%;box-sizing:border-box;background:#071524;color:#edf5ff;border:1px solid #27405d;border-radius:8px;padding:9px}button{margin-top:12px;border:0;border-radius:8px;background:#64a8ff;color:#06111e;font-weight:800;padding:10px 13px;cursor:pointer}[data-message]{color:#91a7bf;margin-top:9px}[data-failed=true]{color:#ff667d}</style><div class="box"><strong>Connect a provider</strong><label>Provider</label><select data-provider><option>Loading…</option></select><button data-connect>Authorize connection</button><div data-message>Validating secure session…</div></div>`;
      this.shadowRoot.querySelector("[data-connect]").onclick = () => this.connect();
    }

    async json(path, body) {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body),
      });
      const value = await response.json();
      if (!response.ok) {
        const error = value.error || {};
        const failure = new Error(error.detail || "Warden request failed");
        failure.code = error.code || "request_failed";
        throw failure;
      }
      return value;
    }

    async load() {
      if (!this.sessionToken) throw new Error("A backend-minted session token is required");
      const session = await this.json("/connect/sessions/inspect", {session_token: this.sessionToken});
      const select = this.shadowRoot.querySelector("[data-provider]");
      select.replaceChildren(...session.allowed_providers.map((provider) => {
        const option = document.createElement("option"); option.value = provider;
        option.textContent = provider; return option;
      }));
      this.message("Choose a provider to continue.");
    }

    async connect() {
      const button = this.shadowRoot.querySelector("[data-connect]");
      button.disabled = true;
      try {
        const provider = this.shadowRoot.querySelector("[data-provider]").value;
        const body = await this.json(`/connect/${encodeURIComponent(provider)}/start`, {
          session_token: this.sessionToken,
        });
        const popup = window.open(body.connect_url, "warden-connect", "popup,width=620,height=760");
        if (!popup) throw Object.assign(new Error("Allow popups to complete authorization"), {code: "popup_blocked"});
        this.message("Waiting for provider authorization…");
        const connected = await this.awaitPopup(popup);
        popup.close();
        this.succeed(connected);
      } catch (error) {
        this.fail(error.code || "request_failed", error.message);
      } finally { button.disabled = false; }
    }

    awaitPopup(popup) {
      return new Promise((resolve, reject) => {
        const deadline = Date.now() + 10 * 60 * 1000;
        const cleanup = () => { window.removeEventListener("message", receive); clearInterval(timer); };
        const receive = (event) => {
          if (event.source !== popup || event.data?.type !== "warden-connect-result") return;
          cleanup(); resolve(event.data.detail);
        };
        window.addEventListener("message", receive);
        const timer = setInterval(() => {
          if (popup.closed || Date.now() >= deadline) {
            cleanup();
            reject(Object.assign(new Error("Authorization window closed or expired."), {code: "flow_incomplete"}));
          }
        }, 500);
      });
    }
  }

  if (!customElements.get("warden-connect")) customElements.define("warden-connect", WardenConnect);
})();
