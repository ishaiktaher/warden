# Reference integration evidence

Warden reports integration compatibility and verification as separate facts.
The machine-readable source is `GET /integrations`; aggregate counts are
available at `GET /integrations/summary` and the public showcase reads the
CI-generated `ui/proof.json` file.

## Contract-tested adapters

Three first-party reference manifests are exercised through the hardened REST
dispatcher in CI:

| Integration | Action | Credential boundary | CI evidence |
| --- | --- | --- | --- |
| GitHub Issues | `issues.create` | OAuth grant, bearer injection inside Warden | `tests/test_credentials.py` |
| Slack | `chat.postMessage` | Managed bearer grant, injected inside Warden | `tests/test_reference_integrations.py` |
| Vouchins Admin Blog API | `blog.publish_post` | Managed bearer grant, injected inside Warden | `tests/test_reference_integrations.py` |

The tests validate connector schemas, permitted destinations, native JSON body
forwarding, credential injection and the absence of credentials in agent-visible
output. They do not call live provider accounts and therefore are labeled
`contract_tested`, not `live_verified`.

## Live verification requirements

A provider is promoted to `live_verified` only after a protected CI environment
executes a disposable operation through the complete Warden gateway and stores
a redacted receipt containing the provider object identifier, timestamp, test
environment and cleanup result. Live test credentials must be held by the
configured secrets provider, never repository secrets passed to an agent.

Until those jobs and credentials are configured, Warden truthfully reports zero
live-verified integrations. Catalog entries remain useful compatibility metadata
but are not counted as proof of working provider integrations.
