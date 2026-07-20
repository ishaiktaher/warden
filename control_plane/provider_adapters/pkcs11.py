"""PKCS#11-backed RS256 signing provider for hardware and software HSMs."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization

from ..config import Settings
from ..providers import ProviderError, SigningKey


class Pkcs11SigningProvider:
    name = "pkcs11"

    def __init__(self, settings: Settings):
        if not all((settings.provider_library, settings.provider_token_label,
                    settings.provider_auth_token, settings.signing_key_id)):
            raise ProviderError(
                "pkcs11 requires WARDEN_PROVIDER_LIBRARY, WARDEN_PROVIDER_TOKEN_LABEL, "
                "WARDEN_PROVIDER_AUTH_TOKEN (PIN), and WARDEN_SIGNING_KEY_ID (key label)"
            )
        try:
            import pkcs11
        except ImportError as exc:
            raise ProviderError(
                "Install requirements/providers/pkcs11.txt for pkcs11"
            ) from exc
        self.pkcs11 = pkcs11
        self.token = pkcs11.lib(settings.provider_library).get_token(
            token_label=settings.provider_token_label
        )
        self.pin = settings.provider_auth_token
        self.key_label = settings.signing_key_id
        self.token_label = settings.provider_token_label
        digest = hashlib.sha256(
            f"{self.token_label}:{self.key_label}".encode()
        ).hexdigest()[:24]
        self.key_id = f"pkcs11-{digest}"

    def active_key(self) -> SigningKey:
        try:
            from pkcs11.util.rsa import encode_rsa_public_key

            with self.token.open(user_pin=self.pin) as session:
                public = session.get_key(
                    label=self.key_label,
                    key_type=self.pkcs11.KeyType.RSA,
                    object_class=self.pkcs11.ObjectClass.PUBLIC_KEY,
                )
                der = encode_rsa_public_key(public)
            key = serialization.load_der_public_key(der)
            pem = key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except Exception as exc:
            raise ProviderError("PKCS#11 public key is unavailable") from exc
        return SigningKey(self.key_id, "RS256", pem)

    def sign(self, key_id: str, message: bytes) -> bytes:
        if key_id != self.key_id:
            raise ProviderError("PKCS#11 key ID does not match configured key")
        try:
            with self.token.open(user_pin=self.pin) as session:
                private = session.get_key(
                    label=self.key_label,
                    key_type=self.pkcs11.KeyType.RSA,
                    object_class=self.pkcs11.ObjectClass.PRIVATE_KEY,
                )
                return bytes(private.sign(
                    message, mechanism=self.pkcs11.Mechanism.SHA256_RSA_PKCS
                ))
        except Exception as exc:
            raise ProviderError("PKCS#11 signing failed") from exc
