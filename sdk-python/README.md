# Vouchins Warden Python SDK

Dependency-free Python 3.11+ client and CLI for the Warden agent authorization
control plane.

```bash
pip install vouchins-warden
```

```python
from vouchins_warden import WardenClient

warden = WardenClient(
    "https://warden.example.com",
    access_token=workload_oidc_token,
)

result = warden.execute(
    capability_token=capability,
    runtime_proof=runtime_proof,
    task_id=task_id,
    connector_id="github-issues",
    action="issues.create",
    resource="repo://acme/app",
    environment="prod",
    grant_id=grant_id,
    parameters={"title": "Investigate production alert"},
)
```

The CLI reads credentials only from environment variables:

```bash
export WARDEN_URL=https://warden.example.com
export WARDEN_ACCESS_TOKEN='<workload OIDC token>'
warden health
warden integrations --query GitHub
warden audit-verify
warden execute --file action-request.json
```

`WARDEN_ADMIN_KEY` is supported only for local break-glass development. Never
place capability tokens, runtime proofs, provider credentials, or access tokens
in command-line arguments because process lists and shell histories can expose
them.
