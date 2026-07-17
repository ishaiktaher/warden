# @vouchins/warden

Typed, dependency-free JavaScript SDK for the Warden AI agent control plane.
It supports maintained Node.js 22+, modern browsers, ESM, CommonJS and
TypeScript.

```bash
npm install @vouchins/warden
```

```ts
import { WardenClient } from "@vouchins/warden";

const warden = new WardenClient({
  baseUrl: "https://warden.example.com",
  accessToken: process.env.WARDEN_RUNTIME_TOKEN,
});

const result = await warden.execute({
  capability_token: capability,
  runtime_proof: runtimeProof,
  task_id: taskId,
  connector_id: "github-issues",
  action: "issues.create",
  resource: "repo://acme/app",
  environment: "prod",
  grant_id: githubGrantId,
  parameters: { title: "Agent-created issue" },
});
```

Warden verifies runtime identity, capability, credential grant, layered policy
and approval before resolving a credential or invoking the connector. The SDK
never receives a resolved downstream credential.

See the [repository documentation](https://github.com/ishaiktaher/warden/tree/main/docs)
for agent registration, OAuth connections, policies and production deployment.
