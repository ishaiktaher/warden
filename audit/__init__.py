"""Sanitized, append-only audit trail for Warden agent activity."""

from .trail import record_audit_event

__all__ = ["record_audit_event"]
