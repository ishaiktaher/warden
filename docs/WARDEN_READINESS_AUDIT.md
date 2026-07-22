# AlterAuth parity and readiness audit

Audit date: 2026-07-22

> This is the pre-build competitive baseline that informed the scoped MVP.
> Several P0/P1 gaps below were subsequently implemented; use
> `docs/MVP_BUILD_STATUS.md` for the post-build truth. Historical counts and gap
> statements are intentionally retained here so the before/after decision record
> remains auditable.

## Executive conclusion

Warden is **not yet at AlterAuth product-readiness parity**. Its control-plane
architecture is strong and, in a few areas, stricter than Alter's documented
model: mandatory gateway execution, signed run-bound capabilities, bounded
delegation, layered monotonic policy, connector SSRF defenses, atomic approval
claims, a kill switch, and a hash-chained audit ledger.

The current gap is not mainly the policy engine. It is the complete product
around that engine: end-user identity lifecycle, organization/app administration,
key lifecycle and attenuation, retrieve/proxy ergonomics, production-grade
Connect sessions, a broad CLI, framework adapters, per-provider setup contracts,
SIEM delivery, and evidence from a running production environment.

The appropriate current claim is:

> Warden implements a vendor-neutral agent action and credential control-plane
> baseline. It is not yet a feature-complete or operationally verified substitute
> for AlterAuth.

## Audit method and completeness

The audit used Alter's published `llms.txt` and `llms-full.txt` indexes, not just
the visible landing-page links. The full snapshot contained **202 distinct pages**:

| Documentation area | Pages reviewed | Warden disposition |
|---|---:|---|
| Get Started | 3 | Partial |
| Guides | 7 | Partial |
| Concepts | 8 | Partial to strong |
| Admin | 5 | Material gaps |
| CLI | 20 | Material gaps |
| Connect SDK | 5 | Partial |
| Python SDK | 10 | Partial |
| TypeScript SDK | 9 | Partial |
| OAuth provider reference | 70, including overview | Catalog breadth, little verification |
| Managed-secret reference | 62, including overview | Catalog gap and little verification |
| Errors and security architecture | 2 | Partial to strong |
| **Total** | **202** | **Not parity-ready** |

Every left-navigation page is represented by one of the rows above. Provider
leaf pages are assessed as sets because they repeat the same acceptance contract:
provider-specific authorization URL, token URL, scopes, refresh behavior,
account discovery, revocation, setup instructions, and verification evidence.

Primary comparison source: [Alter documentation](https://docs.alterauth.com/),
[full documentation index](https://docs.alterauth.com/llms.txt).

Status terms:

- **Strong**: implemented with meaningful local tests or stronger controls.
- **Partial**: a usable primitive exists, but documented Alter behavior or
  developer ergonomics are incomplete.
- **Absent**: no equivalent product capability was found.
- **Unverified**: code/configuration exists, but no live or operated evidence exists.

## Section-by-section readiness matrix

### Get Started

| Alter section | Warden status | Evidence and gap |
|---|---|---|
| Alter | Partial | `README.md` explains the architecture and execution path, but Warden lacks an equally concise product contract centered on credentials, policies, and logs. |
| Quickstart | Partial | Setup and demo commands exist. The first successful third-party call still requires significantly more manual control-plane setup than Alter's under-ten-minute path. |
| How Alter works | Strong/partial | `ARCHITECTURE.md` and `BEGINNERS_GUIDE.md` describe a stronger action-gateway model. A short canonical mental model and retrieve-vs-proxy decision guide are missing. |

### Guides

| Alter section | Warden status | Evidence and gap |
|---|---|---|
| Call APIs on behalf of users | Partial | Generic OAuth connections and grants exist. Automatic app-user resolution from a configured customer IDP, ambiguity handling, and first-class retrieve/proxy SDK calls do not. |
| Provision secrets for backend services | Partial | Managed credentials, secret aliases, injection modes, revocation, and gateway-only resolution exist. There is no provider-template setup workflow at Alter's depth. |
| Give an AI agent scoped access | Strong/partial | Agent manifests, runs, capabilities, grant delegation, parent proof, and depth limits are strong. Per-agent key lifecycle and agent-centric SDK objects are incomplete. |
| Propagate identity into memory layers | Absent | No canonical `IdentityContext`, deterministic memory namespace helper, or short-lived signed identity assertion/JWKS contract was found. |
| Add human-in-the-loop approvals | Strong/partial | Exact action/resource gating and atomic single-use claims exist. Missing developer-facing approval URLs, polling/await helpers, approver notification channels, step-up sessions, and retained result APIs. |
| Embed the Connect Widget | Partial | `<warden-connect>` exists and completes OAuth in a popup. It polls connection lists, exposes raw principal/agent/scope inputs, lacks short-lived backend-minted session tokens, multi-provider sessions, stable callback/error types, theming, and analytics hooks. |
| Integrate with Claude Code (MCP) | Partial | Runtime MCP `tools/call` ingress exists. There is no hosted onboarding MCP server or CLI installer that safely merges client configuration and verifies the integration. |

### Concepts

| Alter section | Warden status | Evidence and gap |
|---|---|---|
| Apps & Organizations | Partial | Tenant/owner isolation exists, including PostgreSQL RLS. Full organization membership, admin/member roles, invitations, app lifecycle, and dashboard permission scopes are incomplete. |
| Providers | Partial | Custom OAuth and managed-secret configuration is a sound abstraction. Most catalog entries are labels using a generic path, not provider contracts proven against live services. |
| Credentials | Strong/partial | Connections, independently revocable grants, scoping, expiry, agent delegation, refresh locking, and boundary injection exist. Missing user/group/system/agent principal parity, ancestor-liveness UX, wallet-authored restrictions, and polished resolution semantics. |
| Agents | Strong/partial | Warden's run/task/tool-call identity and signed authority are strong. Missing managed agent CRUD ergonomics, per-agent API keys, deprecate-before-revoke, last-used metadata, scheduled scope changes, and SDK `Agent` clients. |
| Identity | Material gap | Production OIDC authenticates callers, but Warden does not provide per-app IDP configuration, JIT user records, canonical app-user IDs, group memberships, IDP webhook deprovisioning, directory sync, identity export, or memory scopes. |
| Policies | Strong/partial | Versioned layered fail-closed policies, risk inputs, approval gating, and revocation exist. Missing first-class IP/time/json rule authoring, composed decision traces in a policy explorer, dry-run simulation, user-authored rules, and rollback/admin UX. |
| Scopes | Partial | Capability scopes and grant scopes narrow access. Missing a versioned scope catalog, distinct key-management scopes, derived-key attenuation, in-process constraints, provider-scope diagnostics, and deprecation metadata. |
| Audit Logs | Strong/partial | Redaction, correlation, hash chaining, verification, NDJSON export, and immutable anchoring exist. Missing productized search/filter UX, key/principal/grant fields matching the full Alter schema, CSV export, cursor polling API, retention/legal holds, and reliable OCSF delivery. |

### Admin

| Alter section | Warden status | Evidence and gap |
|---|---|---|
| Setting Up an App | Partial | Owners, agents, connectors, policies, and onboarding UI exist. Organization/app creation and a single coherent setup wizard with verification gates do not. |
| Connecting an Identity Provider | Absent for product parity | Global runtime OIDC is not equivalent to customer-configured per-app Auth0/Clerk/Okta/WorkOS/custom OIDC. Missing discovery, locked claim mappings, sign-in, JIT provisioning, signed webhooks, directory import/reconciliation, stable group IDs, and forced revocation behavior. |
| API Keys | Partial | Signing-key rotation/revocation exists for Warden capabilities. Missing runtime/agent/derived key types, one-time plaintext display, key hashes/prefixes, per-key scopes, CIDR restrictions, rate limits, and expiry constraints, deprecation, grace rotation, cascading derived-key revocation, and usage attribution. |
| Wallet Dashboard | Partial | `/connections` lets a principal inspect and revoke connections/grants. It is not a secure IDP-authenticated wallet with session lifecycle, user-authored policy, call history, branding, and configurable suppression. |
| Exporting Audit Logs | Partial/unverified | NDJSON export and pluggable immutable anchoring exist. Missing CSV, paginated cursor ingestion, configurable retention/legal holds, and an at-least-once OCSF 1.5 SIEM worker with retry, dedupe, dead-letter state, and resume. |

### Reference: Python and TypeScript SDKs

Both publishable SDKs are useful but expose only a narrow portion of the
control plane.

| Alter reference set | Warden status | Required parity work |
|---|---|---|
| Client | Partial | Add explicit app/agent clients, key auth, caller/trace context, retry policy, request IDs, redacted object rendering, and stable version reporting. |
| Calling APIs | Partial | Add high-level retrieve/proxy operations, arbitrary HTTP method/path/body support through typed APIs, provider catalog helpers, and synchronous/HITL result unions. |
| Connect & Grants | Partial | Add backend-minted Connect sessions, polling, authentication sessions, managed-secret sessions, CRUD parity, typed grant policy, and ambiguity errors. |
| Agents & Keys | Material gap | Add agent CRUD/status, key mint/list/deprecate/revoke, runtime/agent/derived keys, attenuation, last-used metadata, idempotency replay semantics, and least-privilege defaults. |
| Types | Material gap | Publish complete immutable response types for identity, scopes, approvals, keys, audit, providers, grants, and errors. |
| Errors | Partial | JS has a structured error; Python is much thinner. Define a stable cross-language error-code catalog and typed subclasses. |
| FastAPI / Express / Next.js | Absent | Add request identity middleware, token extraction, lifecycle hooks, and end-to-end examples. |
| LangChain | Absent | Add a policy-aware tool wrapper with identity/run propagation and approval handling. |
| MCP | Partial | Gateway ingress exists; packaged SDK integration, onboarding server, and client configuration helpers do not. |

### Reference: Connect SDK

| Page | Warden status | Gap |
|---|---|---|
| Connect SDK | Partial | A web component exists but is not a separately versioned browser SDK. |
| `create()` | Absent | No singleton/factory with validated configuration and version API. |
| `open()` | Partial | Popup flow exists; secure session-token contract and typed success/error callbacks are missing. |
| Events & callbacks | Material gap | Only a `warden-connected` DOM event exists; there is no stable lifecycle/error/analytics contract. |
| Types | Material gap | No published browser-SDK types or stable error codes. |

### Reference: CLI

Warden installs a CLI, but it currently contains only a small generic HTTP
surface. Alter documents 20 CLI pages covering authentication, apps, keys,
agents, providers, managed secrets, policy, audit, grants, approvals, analytics,
identity providers, project initialization, design validation, diagnostics,
verification, and scripting.

Parity requires:

1. Browser/device authentication and safely stored profiles.
2. JSON/table output, stable exit codes, non-interactive mode, pagination, stdin
   and file secret inputs, and workspace linking.
3. CRUD/lifecycle commands for apps, agents, keys, providers, managed secrets,
   grants, policies, audit, and identity providers.
4. `doctor`-style end-to-end diagnostics.
5. Policy simulation and approval configuration inspection.
6. Local design/implementation verification suitable for CI.
7. Shell completions and secret-safe logging.

### Reference: provider leaf pages

Alter's provider pages are not merely a name catalog. They document defaults,
required scopes, refresh/PKCE behavior, setup steps, credential fields, endpoint
patterns, and provider-specific caveats.

Warden currently reports:

| Metric | Current value |
|---|---:|
| Catalog entries | 106 |
| OAuth entries | 66 |
| Managed-secret entries | 40 |
| Contract-tested entries | 3 |
| Live-verified entries | 0 |
| Catalog-only entries | 103 |

OAuth name coverage is close, but the currently missing Alter providers are
GitLab, Klaviyo, Xero, and Zoom. Apollo.io, monday.com, and Twitter/X are present
under different Warden slugs and should be normalized to avoid compatibility
surprises.

Managed-secret catalog gaps are: AssemblyAI, DataStax Astra DB, ClickHouse,
Apache CouchDB, Deepgram, Apache Druid, Elasticsearch, ElevenLabs, Hugging Face,
InfluxDB, Meilisearch, Milvus, Neo4j Aura, Neon, Neon SQL, OpenSearch, Pinecone,
Qdrant, Replicate, Snowflake, Turso, Typesense, Upstash, and Weaviate.

Adding names is insufficient. Each supported provider needs a versioned manifest
with credential schema, injection mode, allowed hosts, endpoints, scope catalog,
refresh/revocation behavior, setup guide, contract test, and live-verification
record. Until then the UI and API should continue labeling it `catalog_only`.

### Errors and security architecture

| Alter section | Warden status | Evidence and gap |
|---|---|---|
| Errors | Partial | FastAPI errors and a JS error object exist. There is no complete stable error taxonomy, cross-SDK mapping, retryability metadata, or troubleshooting reference. |
| Security Architecture | Strong but unverified | Warden has strong design controls and explicit production gates. Runtime proof remains bearer-based; isolated connector workers, DPoP/mTLS/workload identity, automated rotation, SIEM streaming, recovery drills, penetration testing, and a real operated environment remain outstanding. |

## Highest-priority gaps

### P0 — claims and security boundaries

1. Stop presenting catalog compatibility as provider readiness anywhere outside
   the existing evidence labels. Preserve `catalog_only`, `contract_tested`, and
   `live_verified` in every SDK and UI response.
2. Implement per-app identity providers, canonical users/groups, signed lifecycle
   webhooks, directory reconciliation, and immediate grant revocation on offboarding.
3. Replace long-lived generic admin/runtime credentials with scoped key records:
   hashes, prefixes, types, scopes, expiry, CIDR/rate limits, rotation, deprecation,
   revocation, derived-key ancestry, and audit attribution.
4. Build backend-minted, short-lived Connect sessions. The browser must never be
   trusted to choose `principal_id`, `agent_id`, or authorization scopes directly.
5. Define a stable, cross-language error and decision contract before expanding
   public SDK usage.

### P1 — developer and administrator completeness

1. Expand Python/TypeScript SDKs around typed App, Agent, Grants, Keys, Identity,
   Approval, Audit, and Policy clients.
2. Build the CLI resource model, safe auth/profile storage, scripting contract,
   diagnostics, and policy simulation.
3. Productize the wallet, approval inbox/links, audit explorer/export, provider
   setup, key lifecycle, and organization/app administration.
4. Add FastAPI, Express, Next.js, LangChain, and MCP integration packages with
   tested examples.
5. Add canonical identity export and signed short-lived identity assertions for
   memory and downstream authorization systems.

### P2 — breadth and proof

1. Close provider catalog gaps and write one provider page per supported entry.
2. Raise the initial launch set from catalog-only to contract-tested, then
   live-verified. Start with GitHub, Google, Microsoft, Slack, Salesforce, Notion,
   Stripe, AWS, Supabase, and Vercel.
3. Implement OCSF SIEM streaming with at-least-once delivery, durable cursors,
   dedupe IDs, exponential retry, dead-letter state, and replay.
4. Add production SLOs, load/failure tests, backup/restore evidence, rotation
   drills, tenant isolation proof, external penetration testing, and incident
   runbooks.
5. Publish a documentation site whose navigation mirrors the actual supported
   product surface and whose examples run in CI.

## Release gates for an honest “AlterAuth-ready” claim

Do not claim parity until all of the following are true:

- Every one of the 202 comparison rows is implemented, explicitly declared
  out-of-scope with a documented alternative, or marked preview.
- Public SDKs cover the complete supported API and pass cross-language contract
  tests against the same OpenAPI/error fixtures.
- No provider shown as supported is merely catalog-only; the launch set has live
  verification with dated evidence and scheduled re-verification.
- A customer can complete app setup, IDP setup, provider connection, scoped agent
  call, approval, revocation, and audit export without database or source edits.
- User and group offboarding revokes effective access within the documented SLA.
- Key rotation, derived-key revocation, approval races, refresh races, tenant
  isolation, SSRF, and SIEM retry/replay all have automated adversarial tests.
- Production preflight passes against a real staging environment, backup/restore
  and disaster recovery are rehearsed, and an external security assessment has
  no unresolved critical/high findings.
- The quickstart succeeds from a clean machine in under ten minutes with no
  undocumented steps.

## Verification notes

The repository test command could not be executed in the current base shell
because runtime dependencies (`fastapi`, `python-dotenv`, `requests`,
`cryptography`, and others) are not installed. This is an environment limitation,
not evidence that the tests fail. It does mean this audit cannot promote any
claim from code-present to locally test-verified during this run.

The production documentation itself correctly states that checked-in code and
infrastructure are not proof of an operated environment. That distinction should
remain prominent in all readiness messaging.
