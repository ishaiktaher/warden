# Dependency lockfiles

Warden installs dependencies from hash-locked files generated with
`pip-compile`. Do not edit a `.txt` lockfile manually.

- `../requirements.in` and `../requirements.txt`: production control-plane core.
- `dev.in` and `dev.txt`: linting, typing, testing, and security tooling.
- `providers/*.in` and `providers/*.txt`: optional native SDK packs for AWS,
  Azure, Google Cloud, and PKCS#11. The portable HTTPS and HashiCorp Vault
  providers use core dependencies and need no additional pack.

Regenerate from the repository root with Python 3.11:

```bash
pip-compile --generate-hashes --strip-extras \
  --output-file=requirements/providers/aws.txt requirements/providers/aws.in
```

Use the equivalent paths for other packs. Development locks additionally use
`--allow-unsafe`. CI installs and audits every lock independently.
