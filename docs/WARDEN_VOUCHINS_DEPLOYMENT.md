# Deploying the authenticated control plane at warden.vouchins.com

The current Vercel project is intentionally a read-only showcase. The real
control plane must run from Warden's OCI image with durable PostgreSQL, Redis,
OIDC, signing, secret-custody and audit providers. Pointing DNS at a container
without those dependencies is not a production deployment.

## Repository support

- `deploy/production/` supplies a Kubernetes namespace, the hardened base
  deployment and a TLS ingress for `warden.vouchins.com`.
- `deploy-production-control-plane` is a manually approved GitHub Actions
  workflow. It accepts only an immutable image digest, runs the migration Job,
  performs a zero-downtime rollout and verifies the public readiness response.
- The GitHub `production-control-plane` environment should require a human
  reviewer. Its only cluster credential is `KUBE_CONFIG_BASE64`; prefer a
  narrowly scoped deployment identity rather than a cluster-admin kubeconfig.

## External prerequisites

1. Provision PostgreSQL and Redis with TLS, backups and restore monitoring.
2. Configure the production OIDC application and required tenant, role and
   on-behalf-of claims.
3. Select any supported KMS/HSM, secrets and immutable audit provider. Mixed
   providers are supported.
4. Create `warden-runtime` and `warden-migration-runtime` through an external-secrets
   controller. Do not commit either Secret.
5. Replace the placeholder custody-provider URLs and connector egress hosts in
   the base ConfigMap with reviewed GitHub environment variables. Configure
   `WARDEN_ALLOWED_ORIGINS` with explicit HTTPS customer application origins
   when serving the embedded Connect component.
6. Install an ingress controller and certificate issuer; create or automate the
   `warden-vouchins-tls` Secret.
7. Add explicit NetworkPolicy egress for PostgreSQL, Redis, OIDC, telemetry,
   custody providers and approved connector destinations.
8. Move `warden.vouchins.com` DNS from the showcase deployment to the ingress
   only after staging, tenant-isolation and recovery tests pass.

## Release

Create a `vX.Y.Z` tag to publish an attested GHCR image. Review its provenance
and digest, then run **deploy-production-control-plane** with that digest. The
workflow will fail before rollout if migration or readiness fails.

DNS, OIDC, cloud resources, provider credentials and production approvals are
external authority and therefore cannot be created by this repository alone.
