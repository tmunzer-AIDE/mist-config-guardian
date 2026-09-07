"""Authenticated encryption for persisted credentials."""

import base64
import binascii
import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mist_config_guardian_backend.config import Settings

_FORMAT_VERSION = "v1"
_NONCE_BYTES = 12
_MIST_CREDENTIAL_CONTEXT = "mist-api-credential"
_LEGACY_MIST_CREDENTIAL_CONTEXT = "service-token"


class CredentialDecryptionError(ValueError):
    """Raised when encrypted credential data cannot be authenticated."""


class CredentialVault:
    """Encrypt and decrypt credentials with AES-256-GCM."""

    def __init__(self, settings: Settings) -> None:
        secret = settings.credential_encryption_key.get_secret_value().encode()
        self._key = hashlib.sha256(secret).digest()

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a non-empty credential using a unique nonce."""
        return self.encrypt_for_context(plaintext, context=_MIST_CREDENTIAL_CONTEXT)

    def encrypt_for_context(self, plaintext: str, *, context: str) -> str:
        """Encrypt a secret and bind it to its intended storage context."""
        if not plaintext:
            msg = "Credential must not be empty"
            raise ValueError(msg)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(self._key).encrypt(
            nonce,
            plaintext.encode(),
            self._associated_data(context),
        )
        payload = base64.urlsafe_b64encode(nonce + ciphertext).decode()
        return f"{_FORMAT_VERSION}:{payload}"

    def decrypt(self, encrypted_value: str) -> str:
        """Authenticate and decrypt a credential."""
        plaintext, _replacement = self.decrypt_with_migration(encrypted_value)
        return plaintext

    def decrypt_with_migration(
        self,
        encrypted_value: str,
    ) -> tuple[str, str | None]:
        """Decrypt current or legacy data and return optional replacement ciphertext."""
        try:
            plaintext = self.decrypt_for_context(
                encrypted_value,
                context=_MIST_CREDENTIAL_CONTEXT,
            )
        except CredentialDecryptionError as current_error:
            try:
                plaintext = self.decrypt_for_context(
                    encrypted_value,
                    context=_LEGACY_MIST_CREDENTIAL_CONTEXT,
                )
                return plaintext, self.encrypt(plaintext)
            except CredentialDecryptionError:
                raise current_error from None
        else:
            return plaintext, None

    def decrypt_for_context(self, encrypted_value: str, *, context: str) -> str:
        """Decrypt a secret only in the context where it was encrypted."""
        version, separator, payload = encrypted_value.partition(":")
        if not separator or version != _FORMAT_VERSION:
            msg = f"Unsupported credential format: {version or 'missing'}"
            raise CredentialDecryptionError(msg)

        try:
            decoded = base64.urlsafe_b64decode(payload.encode())
        except (binascii.Error, ValueError) as exc:
            msg = "Encrypted credential is not valid base64"
            raise CredentialDecryptionError(msg) from exc

        nonce, ciphertext = decoded[:_NONCE_BYTES], decoded[_NONCE_BYTES:]
        if len(nonce) != _NONCE_BYTES or not ciphertext:
            msg = "Encrypted credential payload is incomplete"
            raise CredentialDecryptionError(msg)

        try:
            return (
                AESGCM(self._key)
                .decrypt(
                    nonce,
                    ciphertext,
                    self._associated_data(context),
                )
                .decode()
            )
        except (InvalidTag, UnicodeDecodeError) as exc:
            msg = "Encrypted credential could not be authenticated"
            raise CredentialDecryptionError(msg) from exc

    @staticmethod
    def _associated_data(context: str) -> bytes:
        return f"mist-config-guardian:{context}:v1".encode()
