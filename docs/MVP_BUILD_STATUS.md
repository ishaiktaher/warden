# Warden usable-MVP build status

Date: 2026-07-22

This build follows the scoped MVP brief. It does not claim full AlterAuth parity.

## Ordered delivery report

| Step | Result | Automated proof | Explicitly deferred |
|---|---|---|---|
| 1. Error contract | Complete | `test_runtime_key_is_attributed_then_revoked_with_typed_error`; Python/JS SDK error tests | Broader troubleshooting reference |
| 2. Connect sessions | Complete | `test_connect_session_is_signed_scoped_expiring_and_single_use`; widget boundary regression | Theming and analytics |
| 3. Scoped keys | Complete | Key lifecycle/cascade and gateway-attribution MVP tests | Advanced attenuation and scheduled rotation |
| 4. Per-app identity | Complete for one OIDC provider | JIT, invalid-signature, synchronous-deprovision MVP test | Multi-IDP, directory sync, group reconciliation |
| 5. GitHub vertical slice | Complete with mocked OAuth/provider transport | API credential flow plus gateway, approval, revocation and audit tests | Live external call without customer sandbox credentials |
| 6. Typed SDK clients | Partial | Five Python SDK tests; six JS SDK tests and TypeScript compilation | OpenAPI-generated request/response models |
| 7. Approval inbox | Complete | Approver isolation, resolution, and forbidden-access test | Slack/Teams/webhook fan-out |
| 8. Audit usability | Complete | Principal/key filters, cursor page, and CSV test | OCSF delivery and retention/legal-hold product work |
| 9. Five provider contracts | Contract-complete, not live-verified | Exact-set and HTTPS/endpoint contract tests | Live verification until sandbox accounts are supplied |

## Completed P0

- Stable API errors expose `code`, `detail`, `retryable`, and `request_id`.
  Python and TypeScript provide code-specific exception subclasses.
- Connect sessions are backend-minted, HMAC-signed, limited to ten minutes,
  provider/scope constrained, hash-backed and atomically single-use. The widget
  accepts only `session-token` and emits `{type, code, detail}` results.
- Runtime, agent and derived keys use one-time plaintext and hash-only storage,
  with prefix, scopes, expiry, CIDR allowlist, deprecation, recursive revocation,
  last-used time and audit `key_id` attribution.
- Each app can configure exactly one OIDC provider. RS256 tokens are verified
  through discovery/JWKS, users are JIT-provisioned, and a signed deprovision
  webhook synchronously revokes grants and sessions.

Proof lives in `tests/test_mvp.py`: signed-session success/replay rejection,
key lifecycle/cascade, JIT identity and invalid webhook rejection, gateway key
attribution, and typed rejection after key revocation.

## Completed P1 portions

- Python resource objects: `App`, `Agent`, `Grant`, `Key`, `Approval`, `AuditLog`.
- Matching TypeScript resource objects and API-key authentication.
- Approver-scoped inbox/get/resolve endpoints and polling helpers in both SDKs.
- Optional SMTP-over-TLS notification through `WARDEN_APPROVAL_SMTP_*`; without
  SMTP configuration, requests remain in the inbox and report `inbox_only`.
- Audit filtering by principal, agent, key, action and date, cursor paging, and
  streaming CSV export alongside NDJSON.

The SDK objects are present, but complete request/response model generation from
OpenAPI is not finished. This portion remains partial and must not be described
as generated SDK parity.

## Provider evidence

The exact requested OAuth contracts—GitHub, Google, Slack, Notion and Stripe—pin
HTTPS authorization, token, API and identity endpoints and are covered by
`tests/test_provider_contracts.py`. Existing managed Slack and Vouchins Admin API
contract evidence remains unchanged.

No sandbox credentials were supplied for external provider calls. GitHub uses
mocked OAuth responses in the automated suite; Google, Slack, Notion and Stripe
have static hardened contract tests. They are therefore `contract_tested`, never
`live_verified`. Every other untested entry remains `catalog_only` in API/UI data.

## Explicitly deferred

No new CLI surface, framework package, multi-IDP support, directory sync, group
reconciliation, Wallet product, OCSF streaming, remaining provider work,
advanced attenuation, policy explorer/rollback, load testing, penetration test,
or disaster-recovery scaffolding was added.
