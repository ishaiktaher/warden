# Changelog

This project follows Semantic Versioning. Release notes document API, schema,
policy and SDK compatibility separately.

## 0.2.0 - Unreleased

- Changed the JavaScript SDK support floor to maintained Node.js 22 and added
  Node.js 24 verification.
- Added the publishable `vouchins-warden` Python SDK and `warden` CLI with a
  PyPI trusted-publishing workflow.
- Added guided application, agent, connector, grant, policy and first-call
  onboarding to the authenticated control plane.
- Added a visual monotonic policy builder, embedded OAuth Connect component
  and user-facing connection/grant wallet.
- Added contract-tested GitHub, Slack and Vouchins Admin Blog API reference
  integrations plus the bounded Vouchins blog publishing agent.
- Added evidence levels that distinguish catalog compatibility,
  contract-tested adapters and live-provider verification.
- Added Kubernetes production overlays and an immutable-digest deployment
  workflow for `warden.vouchins.com`.
- Added CI-generated public proof metadata and replaced derivative pricing and
  positioning with Warden's capability, delegation, self-hosting and
  vendor-neutral custody differentiation.
- Added a read-only public showcase deployment that never instantiates the
  credential-bearing control plane.
- Upgraded GitHub Pages and checkout actions to Node.js 24 releases.

## 0.1.0 - 2026-07-15

- Added the vendor-neutral Warden identity and action control plane.
- Added RS256 capabilities, delegation, approvals and layered policies.
- Added credential connections, GitHub OAuth, managed credentials and
  independently revocable agent grants.
- Added REST, MCP, A2A and Python SDK ingress.
- Added the `@vouchins/warden` JavaScript/TypeScript npm package.
- Added hosted integration documentation and production deployment guidance.
- Added DNS-pinned, TLS-hostname-verified connector egress with bounded
  streaming responses to prevent SSRF rebinding and memory exhaustion.
- Separated constant-time health probes from authenticated full-ledger audit
  verification.
- Added hashed Python dependency locks, immutable CI action and container
  references, secret scanning, minimal workflow permissions, and runtime
  compatibility matrices.
