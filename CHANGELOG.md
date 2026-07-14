# Changelog

This project follows Semantic Versioning. Release notes document API, schema,
policy and SDK compatibility separately.

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
