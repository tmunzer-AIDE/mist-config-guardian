"""Snapshot field-level secret protection tests."""

import pytest
from pydantic import SecretStr

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)
from mist_config_guardian_backend.snapshots.secrets import (
    find_unavailable_secrets,
    format_secret_path,
    protect_configuration,
    protected_fingerprint,
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


def test_protection_records_a_comparison_fingerprint() -> None:
    """Equal secrets share a fingerprint so a diff need not decrypt them."""
    vault = CredentialVault(Settings(environment="test", credential_encryption_key=SecretStr("unit-test-key")))
    fields = frozenset({"psk"})

    first = protect_configuration({"psk": "same-value"}, vault, sensitive_fields=fields)
    second = protect_configuration({"psk": "same-value"}, vault, sensitive_fields=fields)
    other = protect_configuration({"psk": "different-value"}, vault, sensitive_fields=fields)

    # Ciphertext differs every time because each encryption uses a fresh nonce.
    assert first["psk"]["$encrypted"] != second["psk"]["$encrypted"]
    assert protected_fingerprint(first["psk"]) == protected_fingerprint(second["psk"])
    assert protected_fingerprint(first["psk"]) != protected_fingerprint(other["psk"])
    assert "same-value" not in str(first)


def test_reveal_ignores_the_fingerprint_sibling() -> None:
    """Revealing a protected value is unaffected by the stored fingerprint."""
    vault = CredentialVault(Settings(environment="test", credential_encryption_key=SecretStr("unit-test-key")))
    protected = protect_configuration({"psk": "secret-value"}, vault, sensitive_fields=frozenset({"psk"}))

    assert reveal_configuration(protected, vault) == {"psk": "secret-value"}


# Locations of secrets Mist will not return, which a restore cannot replay.


def test_masked_nested_secrets_are_rejected() -> None:
    missing = find_unavailable_secrets(
        {
            "auth": {"password": "********"},
            "rules": [{"psk": "real-value"}, {"psk": None}],
        },
        frozenset({"password", "psk"}),
    )

    # Steps, not a dotted string: a key may contain a dot, and a mapping key
    # may look like a list index, so only the steps identify a location.
    assert missing == {("auth", "password"), ("rules", 1, "psk")}


def test_non_secret_masked_values_are_allowed() -> None:
    assert not find_unavailable_secrets(
        {"description": "********"},
        frozenset({"password"}),
    )


def test_a_mapping_key_that_looks_like_an_index_is_its_own_location() -> None:
    """A key spelled "0" is not the first element of a list.

    Both used to be reported as `a.0.psk`. Whatever compares two locations
    would have treated them as one, which is how a mask over one secret came
    to stand in for another.
    """
    keyed = find_unavailable_secrets({"a": {"0": {"psk": "********"}}}, frozenset({"psk"}))
    indexed = find_unavailable_secrets({"a": [{"psk": "********"}]}, frozenset({"psk"}))

    assert keyed == {("a", "0", "psk")}
    assert indexed == {("a", 0, "psk")}
    assert keyed != indexed


def test_a_location_reads_back_as_a_dotted_path_for_a_person() -> None:
    assert format_secret_path(("auth", "servers", 1, "secret")) == "auth.servers.1.secret"
