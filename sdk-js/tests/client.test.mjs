import assert from "node:assert/strict";
import test from "node:test";

import { WardenClient, WardenError } from "../dist/esm/index.js";

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

test("execute adds authorization, defaults, and a unique nonce", async () => {
  const calls = [];
  const client = new WardenClient({
    baseUrl: "https://warden.example.com/",
    accessToken: "runtime-identity-token",
    fetch: async (url, init) => {
      calls.push({ url, init, body: JSON.parse(init.body) });
      return jsonResponse({ status: "executed", tool_call_id: "tool-1", result: {} });
    },
  });
  const request = {
    capability_token: "capability",
    runtime_proof: "runtime-proof-value-long-enough",
    task_id: "task-1",
    connector_id: "github-issues",
    action: "issues.create",
    resource: "repo://acme/app",
    environment: "prod",
  };

  await client.execute(request);
  await client.execute(request);

  assert.equal(calls[0].url, "https://warden.example.com/actions/execute");
  assert.equal(calls[0].init.headers.Authorization, "Bearer runtime-identity-token");
  assert.equal(calls[0].body.data_classification, "internal");
  assert.notEqual(calls[0].body.request_nonce, calls[1].body.request_nonce);
});

test("grant metadata endpoints encode identifiers and never require credentials", async () => {
  const urls = [];
  const client = new WardenClient({
    baseUrl: "http://127.0.0.1:8000",
    fetch: async (url) => {
      urls.push(url);
      return jsonResponse([]);
    },
  });
  await client.listConnections("user+demo@example.com");
  await client.listGrants("user+demo@example.com");
  assert.deepEqual(urls, [
    "http://127.0.0.1:8000/me/connections?principal_id=user%2Bdemo%40example.com",
    "http://127.0.0.1:8000/me/grants?principal_id=user%2Bdemo%40example.com",
  ]);
});

test("structured HTTP failures become WardenError without exposing authorization", async () => {
  const client = new WardenClient({
    baseUrl: "https://warden.example.com",
    accessToken: "must-not-appear",
    fetch: async () => jsonResponse(
      { detail: "Credential grant is unavailable", code: "grant_revoked" },
      403,
      { "X-Request-ID": "request-123" },
    ),
  });
  await assert.rejects(
    () => client.listGrants(),
    (error) => {
      assert.ok(error instanceof WardenError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "grant_revoked");
      assert.equal(error.requestId, "request-123");
      assert.equal(String(error).includes("must-not-appear"), false);
      return true;
    },
  );
});

test("non-local plaintext control-plane URLs are rejected", () => {
  assert.throws(
    () => new WardenClient({ baseUrl: "http://warden.example.com" }),
    /must use HTTPS/,
  );
});
