# Test portal build status

Date: 2026-07-22

## Authorized prerequisites

| Item | Result | Proof |
|---|---|---|
| Browser OIDC PKCE/session | Complete | Login, replay, expiry/tamper, CSRF and server-side logout tests in `tests/test_portal_prerequisites.py` |
| `wus_` API authentication | Complete | Principal binding and typed expired/revoked/tampered rejection tests |
| App/identity/user reads | Complete | Owner-scoped list/config/user endpoint test, including secret redaction and foreign-app rejection |
| Development GitHub transport | Complete | Dedicated `control_plane.dev_portal:app`; production route-absence and full synthetic OAuth callback tests |
| Enforcement traces | Complete | Ordered success, policy denial/skips, explicit unrecorded, and zero-unrecorded resumed-call tests |
| Minimal SDK methods | Complete | Python resource tests and JavaScript portal-surface/CSRF tests |

## Portal screen report

| Step | Screen built | Component/browser proof | Left out |
|---|---|---|---|
| 1 | OIDC sign-in, clean-local bootstrap, canonical JIT user and logout | PKCE/session API tests plus portal screen/SDK component test | Remember-me and session management |
| 2 | App creation, one-IDP configuration, current config/users, signed deprovision | Owner-scope API test and SDK-only portal component assertion | Multi-IDP/directory/group reconciliation |
| 3 | Five live catalog labels, token-only widget, connections/grants and revoke | Synthetic GitHub end-to-end callback plus widget popup component test | Non-GitHub mock transports |
| 4 | Agent create/approve; runtime/agent/derived keys; one-time value; deprecate/revoke cascade | SDK endpoint test and existing lifecycle/cascade backend test | Rotation scheduler and advanced attenuation |
| 5 | GitHub-shaped gateway form with real ordered enforcement trace | Full approval/resume/revoke/trace vertical-slice test | Live external dispatch; local emulator is visibly synthetic |
| 6 | Scoped approval inbox with approve/deny and automatic paused-call resume | Full vertical slice and SDK approval surface test | Notification fan-out beyond MVP email |
| 7 | Principal/agent/key/action/date filters, cursor pages and CSV | SDK CSV/resource tests and existing audit filter/export tests | SIEM/OCSF UI |

The portal JavaScript imports the generated browser artifact of the existing
TypeScript SDK and contains no direct `fetch()` calls. The browser artifact is
resynchronized on every `sdk-js` build and is included with the `ui` deployment
assets.

GitHub authorization/token/identity responses and the gateway's local dispatch
are synthetic. Audit records explicitly say so. Google, Slack, Notion and Stripe
are displayed as `contract_tested`, never `live_verified`, but this pass does not
add mock or live flows for them.
