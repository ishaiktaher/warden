# Production deployment and operations

Warden's production core is vendor-neutral: an OCI container, PostgreSQL,
Redis, OIDC and OpenTelemetry. Cryptographic signing, secret custody and audit
anchoring are ports selected independently at deployment time. See
`docs/PROVIDERS.md`.

## Implemented controls

- Generic OIDC verification including issuer, audience, expiry, not-before,
  subject, tenant, agent role and on-behalf-of identity.
- Pooled PostgreSQL persistence with forced tenant row-level security.
- Pluggable RS256 KMS/HSM signing; private key material never enters Warden when
  an external provider is selected.
- Pluggable secret storage and opaque reference resolution.
- Pluggable immutable audit anchoring with recorded provider receipts.
- Portable HTTPS providers, native `module:factory` plugins, and first-party
  optional AWS, Azure, Google Cloud, Vault and PKCS#11 packs kept out of the
  core dependency set.
- Redis distributed rate limiting, durable idempotency and atomic approval
  claiming before connector invocation.
- Canonical resource validation and hardened HTTPS connector egress.
- Structured request logs, correlation IDs, security headers and OTLP export.
- CI gates for unit tests, Ruff, mypy, Bandit and dependency auditing.

## Valid deployment combinations

These are examples, not an exhaustive list:

| Compute | Database/cache | Signing | Secrets | Audit |
|---|---|---|---|---|
| Kubernetes anywhere | PostgreSQL + Redis | `vault_transit` or `pkcs11` | `vault_kv2` | immutable HTTP target |
| Azure Container Apps/AKS | Azure PostgreSQL + Redis | `azure_key_vault` | `azure_key_vault` | `azure_blob` |
| Google Cloud Run/GKE | Cloud SQL + Memorystore | `gcp_kms` | `gcp_secret_manager` | `gcp_storage` |
| AWS ECS/EKS | RDS + ElastiCache | optional `aws_kms` | optional `aws_secrets_manager` | optional `aws_s3` |
| Private data center | PostgreSQL + Redis | `pkcs11` | `vault_kv2` | SIEM/WORM HTTP gateway |

Mixing providers is supported. A customer is not required to use the same
vendor for compute, identity, signing, secrets, audit, database or telemetry.

## Required operator inputs

1. Production PostgreSQL and Redis endpoints with TLS, backups and tested
   restore procedures.
2. An OIDC issuer whose tokens provide Warden's required claims and MFA for
   administrative identities.
3. Non-local signing, secrets and audit providers selected through environment
   configuration. Provider credentials should use workload identity where the
   selected platform supports it.
4. TLS ingress, DNS, DDoS/WAF controls and a restricted connector egress path.
5. An OTLP collector/SIEM target and operational alert routing.
6. An immutable, scanned container image and reviewed deployment manifests.

## Rollout

1. Run provider conformance tests for the selected adapters.
2. Build the core image or an image containing only the chosen optional plugin.
3. Apply infrastructure in staging and verify tenant/OIDC role mappings.
4. Rehearse `python -m scripts.migrate` and rollback from a restored database
   snapshot using a dedicated DDL role. Application roles should not have DDL.
5. Run tenant-isolation, concurrency, SSRF, authorization and load suites.
6. Inject provider, database, cache and downstream failures and reconcile every
   `processing` action and `uncertain` approval.
7. Anchor the audit chain and independently verify the retention receipt.
8. Canary the release, observe SLOs, then increase traffic.

The Kubernetes manifest in `deploy/k8s.yaml` is a secure template, not a
drop-in environment definition. Its default-deny policy intentionally permits
only cluster DNS; operators must add explicit egress rules for their database,
Redis, OIDC, OTLP, custody providers and approved connectors. Replace the image
placeholder with a reviewed digest and supply `warden-runtime` from an external
secret controller. If a selected cloud workload-identity provider requires a
projected service-account token, enable it narrowly for that service account.

Vercel can host the documentation or a development showcase. It should not be
treated as the durable production control plane unless every required stateful
dependency and custody provider is external and the deployment has passed the
same staging, tenant-isolation and recovery gates as the container deployment.

Production application startup verifies the required schema but does not alter
it. `WARDEN_AUTO_MIGRATE=true` exists for controlled migration environments and
must not be enabled on normal application pods. The checked-in migration Job
uses a separate secret so DDL authority can be removed before traffic starts.

## Remaining high-assurance gates

The runtime proof remains an application bearer secret; use mTLS, DPoP or cloud
workload identity for high-assurance agents. Run external connectors in isolated
workers behind a real egress firewall. Add scheduled audit anchoring, SIEM
streaming, automated secret/key rotation, data-retention jobs, cross-region
recovery and an external penetration test before regulated workloads.

The checked-in AWS Terraform remains a reference deployment only. The native
runtime integrations are not AWS-specific; equivalent infrastructure modules
can consume the same core image and provider interfaces without altering
control-plane business logic.
