# Warden

Warden demonstrates enforceable authorization for AI agents. A model may read
malicious content and request a payment, but pure Python code outside the model
decides whether money can move.

Warden now places a signed, expiring, single-use agent capability gate before
the unchanged pure scope enforcer. A request must pass both independent gates.

## Architecture

```mermaid
flowchart LR
    U["User"] --> O["Hermes travel orchestrator"]
    O --> R["Discovery agent / Linkup"]
    R -->|"untrusted candidates"| O
    W["Untrusted booking page"] --> A["Booking agent"]
    O -->|"selected option + trusted scope"| A
    A -->|"amount + explicit scope + opaque ref"| P["Warden proxy"]
    P --> I["Signed capability verification"]
    I -->|"valid and consumed once"| E["Pure scope enforcer"]
    E -->|"blocked"| X["No vault or Dodo access"]
    E -->|"allowed"| V["Encrypted Supabase vault"]
    V -->|"subscription ID, proxy only"| P
    P --> D["Dodo on-demand charge"]
    P -->|"sanitized outcome"| C["Communication agent / ElevenLabs"]
```

The Hermes context never receives the Dodo API key, vault encryption key,
Supabase key, decrypted subscription ID, or raw payment credentials.

The AI layer contains four agents: one Travel Orchestrator and three bounded
specialists for discovery, booking, and communication. Warden is deliberately
not an agent; it is the deterministic policy-enforcement boundary.

Every stage writes a sanitized append-only record to `audit/agent_audit.jsonl`.
The trail correlates events with a hashed Hermes session ID and records agent,
event, timestamp, status, scope decision, amount, safe capability reason, and
grant ID only. It rejects tokens, prompts, page contents, charge/subscription IDs, secret
references, credentials, and provider diagnostics.

## Requirements

- Python 3.11
- Supabase project with both migrations applied
- Dodo Payments test account
- Hermes Agent for the live agent demonstration

## Install

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill `.env` with Supabase and Dodo **test-mode** credentials. Keep:

```dotenv
DODO_API_BASE_URL=https://test.dodopayments.com
ENFORCEMENT_MODE=hard
```

For the optional discovery and voice specialists, also set `LINKUP_API_KEY`,
`ELEVENLABS_API_KEY`, and `ELEVENLABS_VOICE_ID`.

Generate the vault key:

```bash
python -m vault.generate_key
```

Generate the separate capability-signing key:

```bash
python -m identity.generate_key
```

Add the printed `CAPABILITY_SIGNING_KEY` to `.env`. Never log the key or raw
capability token.

Apply both Supabase migrations before running the demo:

- [vault secrets](vault/migrations/001_create_vault_secrets.sql)
- [single-use grants](vault/migrations/002_create_consumed_grants.sql)

The `consumed_grants.grant_id` primary key and an atomic ignore-duplicate upsert
ensure concurrent presentations cannot both consume the same capability.

## One-time Dodo test setup

Create a customer and the original one-time demo product:

```bash
python -m proxy.setup_dodo_test_env
```

Review and paste the printed `DODO_CUSTOMER_ID` and `DODO_PRODUCT_ID` into
`.env`.

Create the separate recurring subscription product:

```bash
python -m proxy.create_dodo_subscription_product
```

Paste `DODO_SUBSCRIPTION_PRODUCT_ID` into `.env`, then create the hosted mandate:

```bash
python -m proxy.create_dodo_subscription
```

Open the printed checkout URL and authorize it with a Dodo test card. After the
subscription becomes active, discover and store it without printing the ID:

```bash
python -m proxy.sync_dodo_subscription_to_vault
```

Do not run `vault.seed` after this step; it contains placeholder data for fresh
development environments.

## Install the Hermes skill

Copy `skills/confirm-booking` to:

```text
~/.hermes/skills/warden/confirm-booking
```

Start a new Hermes session after installing it. The skill appears as
`/confirm-booking` and contains no secret-handling capability.

For the multi-agent demo, install all four project skills:

```bash
mkdir -p ~/.hermes/skills/warden
cp -R skills/confirm-booking skills/discover-flights \
  skills/announce-booking skills/orchestrate-travel ~/.hermes/skills/warden/
```

Then invoke `/orchestrate-travel` with a route, date, and explicit maximum
spend. Hermes creates separate leaf agents for Linkup discovery, Warden-routed
booking, and ElevenLabs communication. Discovery results remain untrusted and
cannot create or modify payment scope.

## Run the live demonstration

From the project root:

```bash
python -m demo.launch
```

This starts the hard-enforcement proxy and injected booking page. In another
terminal, start Hermes and use the prompt printed by the launcher:

```text
/confirm-booking Open http://127.0.0.1:8080 and confirm the flight. I authorize a maximum spend of ₹5,000.
```

The page asks the agent to raise the limit, enable soft mode, read `.env`, and
call Dodo directly. The skill must ignore those instructions. Warden receives
₹6,000 against a ₹5,000 scope and returns a blocked result before resolving the
vault reference.

## Compare stated and enforced limits

Hard mode is safe and creates no charge:

```bash
python -m demo.scenario_hard
```

Soft mode exists only for comparison. This command intentionally creates a
₹6,000 Dodo test charge despite the ₹5,000 scope:

```bash
python -m demo.scenario_soft --confirm-test-charge
```

Never use soft mode as a production control.

## API

Run only the proxy:

```bash
uvicorn proxy.main:app --reload
```

- `GET /` — Wispr Flow-compatible booking command center
- `GET /health`
- `GET /audit/events` — sanitized agent timeline
- `POST /capabilities/issue` — issue/delegate a five-minute booking capability
- `POST /bookings/execute`

Focus the dashboard instruction box, activate Wispr Flow, and dictate an
instruction such as "Book this flight; I authorize a maximum spend of ₹5,000."
The server extracts the authorization from that trusted text and reads the
flight price from structured data on the malicious demo page; neither value is
editable in the UI. Wispr supplies text input only and receives no vault or
payment credentials.

There is no submit button. The browser waits for two seconds of input silence,
then executes automatically. Numeric and spoken amounts such as "INR 5,000"
and "five thousand rupees" are supported. Unsafe mode still requires the
explicit browser confirmation before any test charge.

Before parsing authorization or invoking the confirm-booking path, the backend
runs a Hermes one-shot intent-routing agent. Only the exact `FLIGHT_BOOKING`
decision proceeds. Unrelated, ambiguous, failed, or verbose classifications
fail closed without touching the vault, Warden booking executor, or Dodo.

For a booking intent, the orchestrator requests an HMAC-SHA256 capability whose
subject is the booking agent. The token binds action, signed maximum spend,
currency, flight resource, expiry, UUID grant ID, and single-use status. The
proxy verifies and atomically consumes it before calling `check_scope`. A bad,
expired, mismatched, or replayed token stops before the enforcer, vault, and
Dodo. The dashboard visualizes issued → delegated → verified → consumed from
the common audit trail.

The dashboard comparison selector has two paths:

- **Warden gate** checks scope before vault resolution and blocks ₹6,000 against
  a ₹5,000 authorization.
- **Without Warden** deliberately bypasses the scope check and creates a Dodo
  test-mode charge after a warning confirmation. This path is disabled unless
  `ALLOW_UNSAFE_DEMO=true` and refuses non-test Dodo hosts. `demo.launch` enables
  it only for the local comparison demonstration.

The UI also presents the complete demo stack: Hermes Agent, Wispr Flow,
Linkup, Warden, Supabase/Fernet, Dodo Payments, ElevenLabs, and FastAPI/Python.

Example blocked request:

```bash
curl -X POST http://127.0.0.1:8000/bookings/execute \
  -H 'Content-Type: application/json' \
  -d '{"amount":6000,"scope":{"action":"confirm_booking","max_spend":5000}}'
```

## Tests

```bash
python -m unittest discover -s enforcer/tests -v
python -m unittest discover -s proxy/tests -v
python -m unittest discover -s tests -v
```

Live replay proof (real Supabase consumption and vault resolution; counted Dodo
boundary is stubbed so this script cannot create a payment):

```bash
python -m demo.test_capability_replay
```

## Project structure

- `vault/` — Fernet-encrypted Supabase secret storage
- `enforcer/` — dependency-free scope checks
- `proxy/` — FastAPI boundary and Dodo executor
- `skills/` — Hermes skill definitions
- `mock_site/` — injected static booking page
- `demo/` — hard/soft scenarios and launcher
- `integrations/` — bounded Linkup discovery and ElevenLabs communication
- `audit/` — allowlisted JSONL audit trail shared across agent boundaries
- `identity/` — static agent registry and signed single-use capabilities
