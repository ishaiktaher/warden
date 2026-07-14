"""Secret aliases resolved only inside connector execution."""

from __future__ import annotations

from datetime import datetime, timezone
import os

from cryptography.fernet import Fernet

from .audit import AuditLedger
from .config import Settings
from .database import Database
from .providers import secrets_provider


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecretsBroker:
    def __init__(self, database: Database, audit: AuditLedger, settings: Settings):
        self.database = database
        self.audit = audit
        self.settings = settings
        self.external = secrets_provider(settings)
        if self.external:
            self.fernet = None
            return
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        key_path = settings.data_dir / "local-secrets.key"
        env_key = os.getenv("CONTROL_PLANE_SECRETS_KEY", "").encode()
        if env_key:
            key = env_key
        elif settings.production:
            raise RuntimeError("CONTROL_PLANE_SECRETS_KEY or an external broker is required")
        else:
            if not key_path.exists():
                key_path.write_bytes(Fernet.generate_key())
                key_path.chmod(0o600)
            key = key_path.read_bytes().strip()
        self.fernet = Fernet(key)

    def store(self, alias: str, value: str, actor: str, provider: str = "local-encrypted") -> None:
        if not alias or not value:
            raise ValueError("Secret alias and value are required")
        storage_alias = self.database.namespace(alias)
        if self.external:
            try:
                provider_name = f"{self.database.current_tenant()}/{alias}"
                encrypted = self.external.put(provider_name, value)
            except Exception as exc:
                raise RuntimeError("Secrets provider rejected the value") from exc
            provider = self.external.name
        else:
            if self.fernet is None:
                raise RuntimeError("Local secret encryption is unavailable")
            encrypted = self.fernet.encrypt(value.encode()).decode()
        now = _now()
        with self.database.connect() as connection:
            connection.execute(
                """INSERT INTO secret_aliases(alias,encrypted_value,provider,status,created_at,rotated_at)
                VALUES(?,?,?,?,?,NULL) ON CONFLICT(alias) DO UPDATE SET
                encrypted_value=excluded.encrypted_value,provider=excluded.provider,
                status='active',rotated_at=excluded.created_at""",
                (storage_alias, encrypted, provider, "active", now),
            )
        self.audit.append("secret.rotated", actor, payload={"alias": alias, "provider": provider})

    def resolve_for_connector(
        self, alias: str, *, connector_id: str, run_id: str, task_id: str, tool_call_id: str
    ) -> str:
        row = self.database.one(
            "SELECT encrypted_value,status FROM secret_aliases WHERE alias=?",
            (self.database.namespace(alias),)
        )
        if not row or row["status"] != "active":
            raise RuntimeError("Secret alias is unavailable")
        self.audit.append(
            "secret.alias_used",
            "secrets-broker",
            run_id=run_id,
            task_id=task_id,
            tool_call_id=tool_call_id,
            payload={"alias": alias, "connector_id": connector_id},
        )
        if self.external:
            try:
                return self.external.get(row["encrypted_value"])
            except Exception as exc:
                raise RuntimeError("Secret alias could not be resolved") from exc
        if self.fernet is None:
            raise RuntimeError("Local secret encryption is unavailable")
        return self.fernet.decrypt(row["encrypted_value"].encode()).decode()

    def revoke(self, alias: str, actor: str) -> None:
        storage_alias = self.database.namespace(alias)
        row = self.database.one(
            "SELECT encrypted_value FROM secret_aliases WHERE alias=?", (storage_alias,)
        )
        if self.external and row:
            try:
                self.external.revoke(row["encrypted_value"])
            except Exception as exc:
                raise RuntimeError("Secrets provider could not revoke the secret") from exc
        self.database.execute(
            "UPDATE secret_aliases SET status='revoked' WHERE alias=?",
            (storage_alias,),
        )
        self.audit.append("secret.revoked", actor, payload={"alias": alias})
