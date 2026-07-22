import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";
import {WardenClient} from "../dist/esm/index.js";

const root = new URL("../../", import.meta.url);

test("portal exposes exactly seven functional SDK-driven screens", () => {
  const html = readFileSync(new URL("ui/portal.html", root), "utf8");
  const script = readFileSync(new URL("ui/portal.js", root), "utf8");
  for (const id of ["signin", "apps", "connect", "agents", "gateway", "approvals", "audit"]) {
    assert.match(html, new RegExp(`<section id="${id}"`));
  }
  assert.match(script, /from "\/sdk\/warden\.js"/);
  assert.doesNotMatch(script, /\bfetch\s*\(/);
  for (const call of ["portalSession", "app.create", "mintConnectSession", "key.mint", "execute", "approval.resolve", "auditLog.page"]) {
    assert.ok(script.includes(call), `screen must drive SDK method ${call}`);
  }
});

test("portal SDK methods preserve CSRF and use the authorized backend surfaces", async () => {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({url, init});
    return new Response(JSON.stringify([]), {status: 200, headers: {"Content-Type": "application/json"}});
  };
  const client = new WardenClient({baseUrl: "https://warden.example", csrfToken: "csrf", fetch: fetcher});
  await client.app.list();
  await client.key.deprecate("key/one");
  await client.approval.list("approver@example.com");
  await client.mintConnectSession({principal_id: "user-1"});
  assert.equal(new URL(calls[0].url).pathname, "/admin/apps");
  assert.equal(new URL(calls[1].url).pathname, "/admin/api-keys/key%2Fone/deprecate");
  assert.equal(calls[1].init.headers["X-CSRF-Token"], "csrf");
  assert.equal(calls[2].init.headers["X-Approver-ID"], "approver@example.com");
  assert.equal(new URL(calls[3].url).pathname, "/admin/connect/sessions");
});

test("Connect component completes from an opaque session and typed popup message", async () => {
  const listeners = new Map();
  const nodes = {
    "[data-provider]": {value: "github", replaceChildren(...items) { this.items = items; }},
    "[data-connect]": {disabled: false},
    "[data-message]": {textContent: "", dataset: {}},
  };
  class Element {
    constructor() { this.attributes = new Map(); this.events = []; }
    attachShadow() { return this.shadowRoot = {innerHTML: "", querySelector: (key) => nodes[key]}; }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    setAttribute(name, value) { this.attributes.set(name, value); }
    dispatchEvent(event) { this.events.push(event); }
  }
  let componentType;
  const popup = {closed: false, close() { this.closed = true; }};
  const context = {
    HTMLElement: Element,
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
    customElements: {get() {}, define(_name, type) { componentType = type; }},
    document: {createElement() { return {value: "", textContent: ""}; }},
    fetch: async (url) => new Response(JSON.stringify(url.endsWith("/inspect")
      ? {allowed_providers: ["github"]}
      : {connect_url: "https://github.example/authorize"}), {status: 200, headers: {"Content-Type": "application/json"}}),
    window: {
      open: () => popup,
      addEventListener(name, handler) { listeners.set(name, handler); },
      removeEventListener(name) { listeners.delete(name); },
    },
    setInterval, clearInterval, setTimeout, Promise,
  };
  vm.runInNewContext(readFileSync(new URL("ui/warden-connect.js", root), "utf8"), context);
  const component = new componentType(); component.setAttribute("session-token", "wcs_opaque_backend_token_abcdefghijklmnopqrstuvwxyz"); component.render(); await component.load();
  const connecting = component.connect();
  await new Promise((resolve) => setTimeout(resolve, 0));
  listeners.get("message")({source: popup, data: {type: "warden-connect-result", detail: {provider_id: "github", account_identifier: "synthetic-octocat", connection_id: "one"}}});
  await connecting;
  assert.equal(component.events.at(-1).detail.type, "success");
  assert.equal(component.events.at(-1).detail.code, "connected");
  assert.equal(component.getAttribute("principal-id"), null);
});
