"""Encrypted secret storage backed by Supabase."""

from .vault import resolve_secret, store_secret

__all__ = ["resolve_secret", "store_secret"]
