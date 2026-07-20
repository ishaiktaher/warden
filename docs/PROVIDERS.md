# Infrastructure provider contract

Warden core depends on three ports, not on a cloud SDK:

- `SigningProvider`: returns an RS256 public key and signs bytes without
  exposing private key material.
- `SecretsProvider`: stores, resolves and revokes opaque secret references.
- `AuditAnchorProvider`: durably anchors a hash-chain head and returns a receipt.

Provider selection is independent for each port. A customer can mix, for
example, an Azure Key Vault signer, HashiCorp Vault secrets and an immutable GCS
audit target.

## Selection

Set `WARDEN_SIGNING_PROVIDER`, `WARDEN_SECRETS_PROVIDER`, and
`WARDEN_AUDIT_PROVIDER`. Supported values are:

- `http`: portable HTTPS contract described below.
- `aws_kms`, `aws_secrets_manager`, `aws_s3`: optional AWS adapters installed by
  `requirements/providers/aws.txt`.
- `azure_key_vault` (signing/secrets) and `azure_blob` (audit): optional Azure
  adapters installed by `requirements/providers/azure.txt`.
- `gcp_kms`, `gcp_secret_manager`, and `gcp_storage`: optional Google Cloud
  adapters installed by `requirements/providers/gcp.txt`.
- `vault_transit` and `vault_kv2`: first-party HashiCorp Vault API adapters that
  use the core `requests` dependency and require no optional provider pack.
- `pkcs11`: direct RSA signing through a PKCS#11 module, installed by
  `requirements/providers/pkcs11.txt`.
- `package.module:factory`: an operator-supplied native plugin. The factory
  receives `Settings` and returns an object implementing the relevant protocol
  from `control_plane.providers`.
- `local`: development only; production rejects it.

The three providers need not come from the same vendor. Vendor-specific SDKs
are isolated in optional requirements and imported only when selected.

## First-party configuration

Provider authentication uses the vendor's standard workload identity chain:
Azure `DefaultAzureCredential`, Google Application Default Credentials, AWS's
default boto3 credential chain, a scoped Vault token, or a PKCS#11 token PIN.
Warden does not accept or persist long-lived cloud credentials through its API.

| Provider | Required Warden settings | Operational prerequisite |
|---|---|---|
| `azure_key_vault` signer | `WARDEN_SIGNING_KEY_ID=https://VAULT.vault.azure.net/keys/KEY/VERSION` | RSA Key Vault/Managed HSM key and `sign`, `get` RBAC |
| `azure_key_vault` secrets | `WARDEN_SECRETS_PROVIDER_URL=https://VAULT.vault.azure.net` | secret `set`, `get`, `delete` RBAC |
| `azure_blob` audit | account URL in `WARDEN_AUDIT_PROVIDER_URL`; container in `WARDEN_AUDIT_TARGET` | Blob immutability support and data contributor RBAC |
| `gcp_kms` | full CryptoKeyVersion resource in `WARDEN_SIGNING_KEY_ID` | `RSA_SIGN_PKCS1_2048_SHA256` (or larger) key version |
| `gcp_secret_manager` | `WARDEN_SECRETS_PREFIX=projects/PROJECT_ID` | create/access/add/destroy-version IAM |
| `gcp_storage` | bucket in `WARDEN_AUDIT_TARGET` | locked retention policy at least as long as requested |
| `vault_transit` | Vault URL; token; RSA key name in `WARDEN_SIGNING_KEY_ID`; optional `WARDEN_PROVIDER_MOUNT` | Transit key type `rsa-2048` or stronger; read/sign policy |
| `vault_kv2` | Vault URL; token; `WARDEN_SECRETS_PREFIX=MOUNT/PATH` | KV v2 data/metadata policy |
| `pkcs11` | module path, token label, PIN, and key label | RSA public/private key objects with the same label |

Vault uses `WARDEN_SIGNING_PROVIDER_URL` or `WARDEN_SECRETS_PROVIDER_URL`,
`WARDEN_PROVIDER_AUTH_TOKEN`, and optional `WARDEN_PROVIDER_NAMESPACE`. PKCS#11
uses `WARDEN_PROVIDER_LIBRARY`, `WARDEN_PROVIDER_TOKEN_LABEL`, the PIN in
`WARDEN_PROVIDER_AUTH_TOKEN`, and the key label in `WARDEN_SIGNING_KEY_ID`.
For production, inject the Vault token or HSM PIN from the workload runtime; do
not commit either value to an environment file.

Example mixed deployment:

```dotenv
WARDEN_SIGNING_PROVIDER=azure_key_vault
WARDEN_SIGNING_KEY_ID=https://security.vault.azure.net/keys/warden-signing/KEY_VERSION
WARDEN_SECRETS_PROVIDER=vault_kv2
WARDEN_SECRETS_PROVIDER_URL=https://vault.internal.example.com
WARDEN_SECRETS_PREFIX=secret/warden/connectors
WARDEN_PROVIDER_AUTH_TOKEN=runtime-injected-vault-token
WARDEN_AUDIT_PROVIDER=gcp_storage
WARDEN_AUDIT_TARGET=warden-prod-audit
```

Audit adapters fail closed. Azure must successfully attach a locked per-blob
immutability policy. Google Cloud must report a locked bucket retention policy
whose duration covers the requested Warden retention before an object is
created. S3 uses compliance-mode Object Lock.

The adapters follow the vendors' current public APIs: [Azure Key Vault
cryptography](https://learn.microsoft.com/en-us/python/api/azure-keyvault-keys/azure.keyvault.keys.crypto.cryptographyclient),
[Azure blob immutability](https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-immutability-policy),
[Google Cloud KMS asymmetric signing](https://cloud.google.com/kms/docs/create-validate-signatures),
[Google Secret Manager](https://cloud.google.com/secret-manager/docs),
[Google Cloud Storage retention policies](https://cloud.google.com/storage/docs/bucket-lock),
[Vault Transit](https://developer.hashicorp.com/vault/api-docs/secret/transit),
[Vault KV v2](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2),
and [python-pkcs11](https://python-pkcs11.readthedocs.io/).

## Conformance

Unit tests exercise every first-party loader, RS256 public-key conversion,
Vault Transit signing, Vault KV v2 lifecycle, and immutable-storage fail-closed
behavior without requiring cloud accounts. To validate a deployment against
real infrastructure in an isolated test account:

```bash
WARDEN_RUN_LIVE_PROVIDER_TESTS=1 \
  python -m unittest tests.test_provider_live -v
```

This creates and revokes a test secret, performs and locally verifies an RS256
signature, and writes one immutable audit anchor. The live test is deliberately
opt-in because immutable objects cannot be cleaned up before retention expires.

## Portable HTTPS contract

All endpoints use HTTPS, a ten-second timeout, no redirects, JSON, and optional
`Authorization: Bearer $WARDEN_PROVIDER_AUTH_TOKEN`.

### Signing

`GET /v1/signing-key` returns:

```json
{"key_id":"key-version","algorithm":"RS256","public_key_pem":"-----BEGIN PUBLIC KEY-----..."}
```

`POST /v1/sign` receives `key_id`, `algorithm`, and `message_base64`, and returns
`{"signature_base64":"..."}`. The provider must perform RSASSA-PKCS1-v1_5 with
SHA-256. Warden verifies the resulting token against the returned public key.

### Secrets

- `PUT /v1/secrets/{url-encoded-name}` with `{"value":"..."}` returns an opaque
  `reference`.
- `GET /v1/secrets/{url-encoded-reference}` returns `{"value":"..."}`.
- `DELETE /v1/secrets/{url-encoded-reference}` revokes it.

The provider must authenticate Warden, encrypt at rest, maintain version/access
logs and never include values in application logs.

### Audit anchors

`POST /v1/audit-anchors` receives `document_base64`, `sha256`, and
`retention_days`, and returns an arbitrary receipt object. The target must
prevent alteration/deletion for the requested retention period. Warden records
the receipt in the next hash-chained event.

## Native plugin example

```python
def create_signer(settings):
    return MyKeyVaultSigner(settings)
```

Configure `WARDEN_SIGNING_PROVIDER=my_company.warden:create_signer`. Native
plugins are trusted deployment code and should be pinned, signed, scanned and
covered by the same conformance tests as `tests/test_providers.py`.
