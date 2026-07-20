# Release runbook

## Python dependency locks

Human-maintained direct dependencies live in `requirements*.in`. Generated
`requirements*.txt` files pin and hash the complete transitive graph. After any
input change, install `pip-tools==7.5.3`, regenerate every matching lock with
`pip-compile --generate-hashes --strip-extras`, and run all provider-pack audits.
Never hand-edit a generated lock file.

## JavaScript SDK

The public package name is `@vouchins/warden`; version `0.1.0` is published on
npm. Releases after that initial manual bootstrap must use GitHub Actions
trusted publishing and provenance.

1. Confirm the publisher owns the `vouchins` npm user scope or has publish
   permission in the `vouchins` npm organization, then enable mandatory 2FA.
2. Do not publish from a maintainer workstation. The one-time bootstrap publish
   is complete; all subsequent releases use the protected workflow below.
3. In npm package settings, configure a GitHub Actions trusted publisher for:
   - repository: `ishaiktaher/warden`
   - workflow: `npm-release.yml`
   - environment: `npm`
4. Protect the `npm` GitHub environment and `sdk-v*` tags with required review.
5. Update `sdk-js/package.json`, `sdk-js/package-lock.json` and `CHANGELOG.md`.
6. Run:

   ```bash
   cd sdk-js
   npm ci
   npm test
   npm pack --dry-run
   ```

7. Inspect the tarball file list. It must not contain `.env`, tests, repository
   history, credentials, source maps with secrets, or backend code.
8. Merge the reviewed release commit, then create the exact matching tag. For
   version `0.2.0`, the tag is `sdk-v0.2.0`.
9. The release workflow verifies the tag/version relationship and publishes
   with npm OIDC trusted publishing and provenance. No long-lived npm token is
   stored in GitHub.
10. Install the exact published version in clean Node 22 and Node 24 projects
   and exercise both `import` and `require` before announcing the release.

Never reuse or overwrite an existing npm version. If a workflow fails after a
version has reached the registry, prepare and review a new patch version.

## Python SDK and CLI

The public distribution is `vouchins-warden`; its source lives in
`sdk-python/` and the installed command is `warden`.

1. Configure a PyPI trusted publisher for repository `ishaiktaher/warden`,
   workflow `python-sdk-release.yml` and protected environment `pypi`.
2. Update `sdk-python/pyproject.toml` and `CHANGELOG.md` together.
3. Run the SDK unit tests, build both distributions and validate them with
   `twine check`.
4. Inspect the wheel and source distribution. They must contain only the SDK,
   typing marker, license and documentation.
5. Merge the reviewed release and create an exact matching tag such as
   `python-sdk-v0.2.0`. The workflow checks the tag/version relationship before
   publishing with PyPI OIDC. No API token is stored in GitHub.
6. Install the exact published version in a clean Python 3.11 environment and
   execute `warden health` against a non-production Warden instance.

Never publish from a maintainer workstation and never reuse a released version.

## Documentation

The documentation is served by the control plane at `/documentation` and is
also independently publishable as a static GitHub Pages site. Enable Pages with
"GitHub Actions" as its source. Changes to `ui/docs.html`, `docs/`, or the SDK
README trigger `docs-pages.yml`; the workflow publishes without requiring API,
database, Redis, OIDC or custody-provider credentials. Attach a custom domain
through the repository Pages settings when one is available.

## Control plane

1. Pin all Python and optional provider dependencies and pass CI/security gates.
2. Apply migrations to staging from a tested backup and verify rollback.
3. Build an immutable image and scan its packages and SBOM.
4. Run PostgreSQL/Redis/OIDC/provider conformance, tenant-isolation, failure and
   load tests in staging.
5. Deploy by digest with a canary or zero-unavailable rolling update.
6. Verify `/live`, `/ready`, OTLP traces, audit anchoring and alert delivery.
7. Revoke the canary through the global kill switch and rehearse rollback.
8. Promote the same digest; do not rebuild between staging and production.

A `v*` tag builds the control-plane image, pushes semantic-version and commit
tags to GHCR, emits an SBOM, and attaches GitHub build provenance. Protect the
`production-release` environment and release tags so this workflow requires
maintainer approval. Deploy only the resulting digest, never a mutable tag.
