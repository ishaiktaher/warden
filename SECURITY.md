# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory flow for `ishaiktaher/warden` and include affected versions,
reproduction steps, impact and any suggested mitigation. Do not include real
credentials, customer records or access tokens.

Maintainers should acknowledge a complete report within three business days,
provide an initial severity assessment within seven business days, and
coordinate disclosure after a fix is available. These are response targets,
not a bug-bounty commitment.

## Supported versions

Until Warden reaches 1.0, only the latest released minor version receives
security fixes. Production operators must pin immutable container digests and
npm versions and subscribe to repository security advisories.

## Security boundaries

Local SQLite, local encryption keys and the fallback administrator key are for
development only. Production mode requires PostgreSQL, Redis, OIDC, external
signing, external secret custody and immutable audit anchoring. See
`docs/PRODUCTION.md` before exposing the service to an agent runtime.
