# Agent Control Plane implementation scope

The attached architecture is treated as the target design. This repository
implements the local control-plane behavior plus a cloud-neutral production baseline:
persistent registries and runtime identities, signed capabilities,
delegation, policy and approvals, a mandatory action gateway, secret brokering,
connector adapters, revocation, rate limiting, kill switches, tamper-evident
audit/export, REST/MCP/A2A facades, and the support-ticket scenario.

Production mode uses PostgreSQL/RLS, OIDC, Redis and pluggable signing, secrets
and immutable-audit providers. Portable HTTPS and native plugin contracts keep
cloud SDKs outside the core; AWS is one optional adapter and Terraform example.
These controls are code paths and infrastructure definitions, not proof of an
operated environment. Claims that require an operator-owned cloud account, OIDC tenant, egress firewall,
OTLP/SIEM collector, DNS/certificates, real connector credentials, staging
tests, backups or incident operations are not active until provisioned and
verified. See `docs/PRODUCTION.md` for the exact release gates.
