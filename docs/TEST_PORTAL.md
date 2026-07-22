# Warden test portal

The test portal is a development console for the scoped MVP. It is not the
customer Wallet product and it does not represent synthetic calls as live
provider verification.

## Start locally

Build the browser SDK and run the dedicated development profile:

```bash
npm --prefix sdk-js run build
.venv/bin/uvicorn control_plane.dev_portal:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/portal`. The standard production entrypoint remains
`control_plane.api:app`; it does not mount the `/_dev/mock/github/*` routes or
select the synthetic provider transport.

For a clean local database, use the sign-in screen's bootstrap form with the
existing development admin key. Supply an OIDC issuer/client whose redirect URI
allows `http://127.0.0.1:8000/portal/auth/callback`, then sign in. The browser
session is server-backed, eight hours maximum, Secure/HttpOnly/SameSite=Lax,
and state-changing cookie requests require the per-session CSRF token.

## Portal sequence

1. Confirm the JIT canonical user on the sign-in screen.
2. Create apps, configure one OIDC provider, inspect users, or send a signed
   deprovision test while the one-time webhook secret remains in page memory.
3. Inspect the five contract labels. In the development entrypoint, GitHub uses
   the dedicated synthetic authorization/token/identity transport; its audit
   records always carry `synthetic: true`.
4. Create and approve an agent, then mint runtime, agent, or derived keys. Raw
   key material is retained only in the current page memory for gateway tests.
5. Run the synthetic GitHub-shaped call. The portal renders the recorded
   capability, grant, policy-layer, approval, credential, and dispatch stages.
6. Approve the paused call; the portal resubmits it with the approval ID and
   displays the completed trace.
7. Filter cursor-paginated audit records or download the same filtered CSV.

Google, Slack, Notion, and Stripe remain visible as `contract_tested`; this pass
does not provide synthetic or live OAuth transports for them.
