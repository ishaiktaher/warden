"""Offline production-configuration checks with secret-safe output."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .config import Settings


@dataclass(frozen=True)
class PreflightResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "ready" if self.ok else "blocked",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def _https_error(label: str, value: str | None) -> str | None:
    if not value or urlparse(value).scheme != "https":
        return f"{label} must be an HTTPS URL"
    return None


def evaluate_production_settings(settings: Settings) -> PreflightResult:
    """Evaluate configuration without contacting any infrastructure provider."""

    errors: list[str] = []
    warnings: list[str] = []

    if not settings.production:
        errors.append("CONTROL_PLANE_ENV must be prod")
    if len(settings.admin_key) < 32 or "replace" in settings.admin_key.lower():
        errors.append("CONTROL_PLANE_ADMIN_KEY must be a non-placeholder value of at least 32 characters")
    if not settings.database_url or not settings.database_url.startswith(
        ("postgresql://", "postgresql+psycopg://")
    ):
        errors.append("DATABASE_URL must use PostgreSQL")
    if not settings.redis_url or not settings.redis_url.startswith(("redis://", "rediss://")):
        errors.append("REDIS_URL must use Redis")
    for label, value in (
        ("WARDEN_PUBLIC_URL", settings.public_url),
        ("WARDEN_OIDC_ISSUER", settings.oidc_issuer),
    ):
        error = _https_error(label, value)
        if error:
            errors.append(error)
    if not settings.oidc_audience:
        errors.append("WARDEN_OIDC_AUDIENCE is required")
    for label, provider in (
        ("WARDEN_SIGNING_PROVIDER", settings.signing_provider),
        ("WARDEN_SECRETS_PROVIDER", settings.secrets_provider),
        ("WARDEN_AUDIT_PROVIDER", settings.audit_provider),
    ):
        if provider == "local":
            errors.append(f"{label} cannot be local in production")

    if settings.signing_provider == "http":
        error = _https_error("WARDEN_SIGNING_PROVIDER_URL", settings.signing_provider_url)
        if error:
            errors.append(error)
    if settings.secrets_provider == "http":
        error = _https_error("WARDEN_SECRETS_PROVIDER_URL", settings.secrets_provider_url)
        if error:
            errors.append(error)
    if settings.audit_provider == "http":
        error = _https_error("WARDEN_AUDIT_PROVIDER_URL", settings.audit_provider_url)
        if error:
            errors.append(error)
    if "http" in {
        settings.signing_provider,
        settings.secrets_provider,
        settings.audit_provider,
    } and not settings.provider_auth_token:
        warnings.append(
            "HTTP providers have no bearer token; confirm that workload identity or mTLS is enforced upstream"
        )
    if settings.auto_migrate:
        warnings.append("WARDEN_AUTO_MIGRATE is enabled; reviewed production migrations are safer")
    if not settings.allowed_egress_hosts:
        warnings.append("No connector egress hosts are allowlisted; external REST actions will be denied")
    if not settings.otlp_endpoint:
        warnings.append("OTLP export is not configured")
    if settings.redis_url and settings.redis_url.startswith("redis://"):
        warnings.append("Redis is not using TLS; restrict it to a private authenticated network or use rediss://")

    return PreflightResult(tuple(errors), tuple(warnings))
