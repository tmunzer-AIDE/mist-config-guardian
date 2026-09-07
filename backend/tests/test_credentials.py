"""Credential encryption tests."""

import pytest

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault


def test_credential_round_trip_does_not_expose_plaintext() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))

    encrypted = vault.encrypt("mist-token-value")

    assert encrypted.startswith("v1:")
    assert "mist-token-value" not in encrypted
    assert vault.decrypt(encrypted) == "mist-token-value"


def test_credential_encryption_uses_unique_nonce() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))

    assert vault.encrypt("same-token") != vault.encrypt("same-token")


def test_tampered_credential_is_rejected() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))
    encrypted = vault.encrypt("mist-token-value")
    replacement = "A" if encrypted[-1] != "A" else "B"

    with pytest.raises(CredentialDecryptionError):
        vault.decrypt(encrypted[:-1] + replacement)


def test_legacy_service_token_context_can_still_be_decrypted() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))
    encrypted = vault.encrypt_for_context("legacy-token", context="service-token")

    assert vault.decrypt(encrypted) == "legacy-token"


def test_legacy_service_token_returns_current_context_replacement() -> None:
    vault = CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))
    encrypted = vault.encrypt_for_context("legacy-token", context="service-token")

    plaintext, replacement = vault.decrypt_with_migration(encrypted)

    assert plaintext == "legacy-token"
    assert replacement is not None
    assert vault.decrypt_for_context(replacement, context="mist-api-credential") == "legacy-token"
