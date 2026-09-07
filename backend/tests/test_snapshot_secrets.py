"""Snapshot field-level secret protection tests."""

import pytest

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)
from mist_config_guardian_backend.snapshots.secrets import (
    protect_configuration,
    reveal_configuration,
)


def test_snapshot_secrets_are_encrypted_recursively() -> None:
    vault = CredentialVault(Settings(environment="test"))
    configuration: dict[str, object] = {
        "name": "Corporate",
        "psk": "wireless-secret",
        "radius": {"password": "radius-secret", "host": "radius.example.com"},
    }

    protected = protect_configuration(
        configuration,
        vault,
        sensitive_fields=frozenset({"psk", "password"}),
    )

    assert "wireless-secret" not in str(protected)
    assert "radius-secret" not in str(protected)
    assert reveal_configuration(protected, vault) == configuration


def test_snapshot_secret_is_bound_to_field_path() -> None:
    vault = CredentialVault(Settings(environment="test"))
    encrypted = vault.encrypt_for_context("secret", context="snapshot:psk")

    with pytest.raises(CredentialDecryptionError):
        vault.decrypt_for_context(encrypted, context="snapshot:password")
