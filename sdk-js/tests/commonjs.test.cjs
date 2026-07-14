const assert = require("node:assert/strict");
const test = require("node:test");

const { WardenClient } = require("../dist/cjs/index.js");

test("CommonJS export can construct and call the client", async () => {
  const client = new WardenClient({
    baseUrl: "https://warden.example.com",
    fetch: async () => new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  });
  assert.deepEqual(await client.health(), { status: "ok" });
});
