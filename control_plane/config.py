"""Runtime configuration with explicit development/production boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import cast

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    database_path: Path
    data_dir: Path
    issuer: str
    audience: str
    admin_key: str
    environment: str
    allowed_egress_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()
    public_url: str = "http://127.0.0.1:8000"
    auto_migrate: bool = False
    database_url: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "roles"
    oidc_on_behalf_of_claim: str = "on_behalf_of"
    oidc_jwks_cache_seconds: int = 300
    redis_url: str | None = None
    otlp_endpoint: str | None = None
    signing_provider: str = "local"
    secrets_provider: str = "local"
    audit_provider: str = "local"
    signing_provider_url: str | None = None
    secrets_provider_url: str | None = None
    audit_provider_url: str | None = None
    provider_auth_token: str | None = None
    signing_key_id: str | None = None
    secrets_prefix: str | None = None
    audit_target: str | None = None
    provider_region: str | None = None
    provider_mount: str | None = None
    provider_namespace: str | None = None
    provider_library: str | None = None
    provider_token_label: str | None = None
    max_request_bytes: int = 1_048_576
    approval_smtp_host: str | None = None
    approval_smtp_port: int = 465
    approval_smtp_from: str | None = None
    approval_smtp_username: str | None = None
    approval_smtp_password: str | None = None

    @property
    def production(self) -> bool:
        return self.environment == "prod"


def load_settings() -> Settings:
    load_dotenv(ROOT / ".env")
    data_dir = Path(os.getenv("CONTROL_PLANE_DATA_DIR", ROOT / "data")).resolve()
    database_path = Path(
        os.getenv("CONTROL_PLANE_DATABASE", data_dir / "control_plane.db")
    ).resolve()
    environment = os.getenv("CONTROL_PLANE_ENV", "dev").strip().lower()
    admin_key = os.getenv("CONTROL_PLANE_ADMIN_KEY", "").strip()
    if environment == "prod" and not admin_key:
        raise RuntimeError(
            "CONTROL_PLANE_ADMIN_KEY is required for break-glass administration"
        )
    if not admin_key:
        admin_key = "local-development-admin-key"
    hosts = tuple(
        host.strip().lower()
        for host in os.getenv("CONTROL_PLANE_ALLOWED_EGRESS_HOSTS", "").split(",")
        if host.strip()
    )
    origins = tuple(
        origin.strip().rstrip("/")
        for origin in os.getenv("WARDEN_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    )
    if environment == "prod" and any(
        origin == "*" or not origin.startswith("https://") for origin in origins
    ):
        raise RuntimeError(
            "Production WARDEN_ALLOWED_ORIGINS must contain explicit HTTPS origins"
        )
    oidc_issuer = os.getenv("WARDEN_OIDC_ISSUER", "").strip().rstrip("/") or None
    oidc_audience = os.getenv("WARDEN_OIDC_AUDIENCE", "").strip() or None
    database_url = os.getenv("DATABASE_URL", "").strip() or None
    redis_url = os.getenv("REDIS_URL", "").strip() or None
    signing_provider = os.getenv("WARDEN_SIGNING_PROVIDER", "local").strip()
    secrets_provider = os.getenv("WARDEN_SECRETS_PROVIDER", "local").strip()
    audit_provider = os.getenv("WARDEN_AUDIT_PROVIDER", "local").strip()
    if environment == "prod":
        missing = [
            name
            for name, value in (
                ("DATABASE_URL", database_url),
                ("WARDEN_OIDC_ISSUER", oidc_issuer),
                ("WARDEN_OIDC_AUDIENCE", oidc_audience),
                ("REDIS_URL", redis_url),
                (
                    "WARDEN_SIGNING_PROVIDER",
                    signing_provider if signing_provider != "local" else None,
                ),
                (
                    "WARDEN_SECRETS_PROVIDER",
                    secrets_provider if secrets_provider != "local" else None,
                ),
                (
                    "WARDEN_AUDIT_PROVIDER",
                    audit_provider if audit_provider != "local" else None,
                ),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Production configuration is incomplete: " + ", ".join(missing)
            )
        database_url = cast(str, database_url)
        oidc_issuer = cast(str, oidc_issuer)
        redis_url = cast(str, redis_url)
        if not database_url.startswith(("postgresql://", "postgresql+psycopg://")):
            raise RuntimeError("Production DATABASE_URL must use PostgreSQL")
        if not oidc_issuer.startswith("https://"):
            raise RuntimeError("Production OIDC issuer must use HTTPS")
        if not redis_url.startswith(("rediss://", "redis://")):
            raise RuntimeError("Production REDIS_URL must use Redis")
    public_url = (
        os.getenv("WARDEN_PUBLIC_URL", "http://127.0.0.1:8000").strip().rstrip("/")
    )
    if environment == "prod" and not public_url.startswith("https://"):
        raise RuntimeError("Production WARDEN_PUBLIC_URL must use HTTPS")
    return Settings(
        database_path=database_path,
        data_dir=data_dir,
        issuer=os.getenv("CONTROL_PLANE_ISSUER", "warden-control-plane"),
        audience=os.getenv("CONTROL_PLANE_AUDIENCE", "warden-action-gateway"),
        admin_key=admin_key,
        environment=environment,
        allowed_egress_hosts=hosts,
        allowed_origins=origins,
        public_url=public_url,
        auto_migrate=os.getenv("WARDEN_AUTO_MIGRATE", "false").strip().lower()
        in {"1", "true", "yes"},
        database_url=database_url,
        oidc_issuer=oidc_issuer,
        oidc_audience=oidc_audience,
        oidc_tenant_claim=os.getenv("WARDEN_OIDC_TENANT_CLAIM", "tenant_id"),
        oidc_roles_claim=os.getenv("WARDEN_OIDC_ROLES_CLAIM", "roles"),
        oidc_on_behalf_of_claim=os.getenv(
            "WARDEN_OIDC_ON_BEHALF_OF_CLAIM", "on_behalf_of"
        ),
        oidc_jwks_cache_seconds=int(os.getenv("WARDEN_OIDC_JWKS_CACHE_SECONDS", "300")),
        redis_url=redis_url,
        otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip() or None,
        signing_provider=signing_provider,
        secrets_provider=secrets_provider,
        audit_provider=audit_provider,
        signing_provider_url=os.getenv("WARDEN_SIGNING_PROVIDER_URL", "").strip()
        or None,
        secrets_provider_url=os.getenv("WARDEN_SECRETS_PROVIDER_URL", "").strip()
        or None,
        audit_provider_url=os.getenv("WARDEN_AUDIT_PROVIDER_URL", "").strip() or None,
        provider_auth_token=os.getenv("WARDEN_PROVIDER_AUTH_TOKEN", "").strip() or None,
        signing_key_id=os.getenv("WARDEN_SIGNING_KEY_ID", "").strip() or None,
        secrets_prefix=os.getenv("WARDEN_SECRETS_PREFIX", "").strip() or None,
        audit_target=os.getenv("WARDEN_AUDIT_TARGET", "").strip() or None,
        provider_region=os.getenv("WARDEN_PROVIDER_REGION", "").strip() or None,
        provider_mount=os.getenv("WARDEN_PROVIDER_MOUNT", "").strip() or None,
        provider_namespace=os.getenv("WARDEN_PROVIDER_NAMESPACE", "").strip() or None,
        provider_library=os.getenv("WARDEN_PROVIDER_LIBRARY", "").strip() or None,
        provider_token_label=os.getenv("WARDEN_PROVIDER_TOKEN_LABEL", "").strip()
        or None,
        max_request_bytes=max(
            16_384, int(os.getenv("WARDEN_MAX_REQUEST_BYTES", "1048576"))
        ),
        approval_smtp_host=os.getenv("WARDEN_APPROVAL_SMTP_HOST", "").strip() or None,
        approval_smtp_port=int(os.getenv("WARDEN_APPROVAL_SMTP_PORT", "465")),
        approval_smtp_from=os.getenv("WARDEN_APPROVAL_SMTP_FROM", "").strip() or None,
        approval_smtp_username=os.getenv("WARDEN_APPROVAL_SMTP_USERNAME", "").strip()
        or None,
        approval_smtp_password=os.getenv("WARDEN_APPROVAL_SMTP_PASSWORD", "").strip()
        or None,
    )
