# Credential connections and grants

Warden separates three concepts that are often incorrectly collapsed into one
token:

1. A **connection** is custody of a provider credential for one human or system
   account.
2. A **grant** limits that connection by Warden actions, HTTP methods, endpoint
   path patterns and expiry.
3. A **capability** authorizes one agent run to perform an action on a resource.

An external action executes only when both the capability and credential grant
are valid and every applicable policy layer allows it. Revoking either authority
blocks the next request without changing the agent prompt or restarting it.

## GitHub OAuth setup

Create a GitHub OAuth app with this callback URL:

```text
https://warden.example.com/oauth/github/callback
```

Set `WARDEN_PUBLIC_URL=https://warden.example.com`, store the OAuth client
secret as a Warden secret alias, then register the provider:

```bash
curl -X POST https://warden.example.com/admin/secrets \
  -H 'Authorization: Bearer <admin-oidc-token>' \
  -H 'Content-Type: application/json' \
  -d '{"alias":"github-oauth-client","value":"<secret>","provider":"oauth-client"}'

curl -X POST https://warden.example.com/admin/oauth/providers/github \
  -H 'Authorization: Bearer <admin-oidc-token>' \
  -H 'Content-Type: application/json' \
  -d '{"provider_id":"github","client_id":"<client-id>","client_secret_alias":"github-oauth-client","default_scopes":["repo"]}'
```

The signed-in user calls `POST /connect/github/start` with the target agent,
Warden action scopes and method/path restrictions. Warden returns a GitHub
authorization URL. The callback validates the one-time state, exchanges the
code, verifies the GitHub identity through `GET /user`, stores the credential
through the configured secrets provider, creates the grant and delegates it to
the selected agent.

GitHub OAuth App tokens without an expiry remain valid until provider or Warden
revocation. If GitHub returns an expiring user access token and refresh token,
Warden refreshes it shortly before expiry. Production refreshes use a Redis
distributed lock to prevent concurrent rotation races.

## Provider-neutral OAuth and integration catalog

`GET /integrations` returns the versioned Warden catalog. For any OAuth entry,
store its client secret and register the provider at
`POST /admin/oauth/providers/{provider_id}` with its authorization, token, API
base and identity URLs, identity ID/label fields, scope separator and maximum
scope set. Start consent at `POST /connect/{provider_id}/start`; the callback is
`/oauth/{provider_id}/callback`. Production requires every provider hostname in
`CONTROL_PLANE_ALLOWED_EGRESS_HOSTS` and rejects non-HTTPS configuration.

The catalog is data-driven: all OAuth entries use the same state, custody,
grant, refresh, revocation and audit controls. Managed-secret entries use the
injection modes below. Custom providers use the same APIs, so adding a vendor
does not require changing the enforcement core.

## Managed credentials

Administrators can onboard API keys, basic credentials, multi-header
credentials or AWS signing material with `POST /admin/connections/managed`.
The credential object is encrypted by the selected secrets provider and is
never returned by list, grant or action APIs.

Connector `credential_mode` values:

- `bearer`: `Authorization: Bearer <token>`
- `custom_header`: configured header name and template
- `multi_header`: configured header templates populated from credential fields
- `basic`: username/password HTTP Basic authentication
- `query`: configured query parameter (use only where the provider requires it)
- `aws_sigv4`: gateway-side SigV4 with configured service and region

REST connectors use a Warden envelope (`resource` plus `parameters`) by
default. APIs that require their native object at the JSON root can set
`credential_config.request_body_mode` to `parameters`. This changes only the
downstream serialization: Warden still authorizes the separate logical
resource before resolving credentials or dispatching the request. Unknown body
modes fail closed.

Use `/me/connections` and `/me/grants` to inspect metadata, delegate a grant to
an agent, or revoke a grant/connection. Audit events contain IDs, restrictions
and decisions but never raw credentials.

## Enforcement order

```text
runtime proof + capability
  -> credential grant ownership/delegation/action/method/path/expiry
  -> layered policy
  -> optional approval
  -> credential resolution/refresh
  -> connector-side injection
  -> redacted output and audit
```

Failure before credential resolution performs no external call.

## Embedded Connect component

The full control-plane deployment serves a dependency-free web component at
`/warden-connect.js`. Add the customer application origin to
`WARDEN_ALLOWED_ORIGINS`, load the module, then provide a function that returns
the signed-in user's Warden access token:

```html
<script src="https://warden.example.com/warden-connect.js" defer></script>
<warden-connect id="provider-connect"
  base-url="https://warden.example.com"
  agent-id="tenant--support-agent"
  grant-scopes="tickets.read,tickets.update"></warden-connect>
<script>
  document.querySelector("#provider-connect").getAccessToken = async () =>
    obtainWorkloadAccessToken();
</script>
```

The component opens provider consent in a popup and polls only connection
metadata. OAuth tokens stay in Warden custody. Production CORS rejects wildcard
origins and accepts only explicit HTTPS origins.
