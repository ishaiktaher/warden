"""Encrypt and store secrets without exposing plaintext to callers."""

import os
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from supabase import Client, create_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_configuration() -> tuple[Fernet, Client]:
    load_dotenv(PROJECT_ROOT / ".env")

    encryption_key = os.getenv("VAULT_ENCRYPTION_KEY")
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    missing = [
        name
        for name, value in (
            ("VAULT_ENCRYPTION_KEY", encryption_key),
            ("SUPABASE_URL", supabase_url),
            ("SUPABASE_KEY", supabase_key),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return Fernet(encryption_key.encode()), create_client(supabase_url, supabase_key)


def store_secret(ref: str, plaintext_value: str) -> None:
    """Encrypt a plaintext value and store it under ``ref``."""
    if not ref:
        raise ValueError("ref must not be empty")

    fernet, supabase = _load_configuration()
    encrypted_value = fernet.encrypt(plaintext_value.encode()).decode()
    (
        supabase.table("vault_secrets")
        .upsert(
            {"ref": ref, "encrypted_value": encrypted_value},
            on_conflict="ref",
        )
        .execute()
    )


def resolve_secret(ref: str) -> str:
    """Fetch and decrypt the secret stored under ``ref``."""
    # !!! SECURITY BOUNDARY — PROXY CODE ONLY !!!
    # This function returns plaintext credentials. It MUST ONLY be called from
    # proxy/ code and MUST NEVER be imported into Hermes agent code, skills, tool
    # descriptions, prompts, logs, or anything else that can enter agent context.
    # Keeping resolution behind the proxy prevents prompt injection from turning
    # an opaque secret reference into credential disclosure.
    if not ref:
        raise ValueError("ref must not be empty")

    fernet, supabase = _load_configuration()
    response = (
        supabase.table("vault_secrets")
        .select("encrypted_value")
        .eq("ref", ref)
        .limit(1)
        .execute()
    )
    if not response.data:
        raise KeyError(f"Secret ref not found: {ref}")

    encrypted_value = response.data[0]["encrypted_value"]
    return fernet.decrypt(encrypted_value.encode()).decode()
