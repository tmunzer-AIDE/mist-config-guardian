"""Restore authorization safety checks."""

from mist_config_guardian_backend.services.restore_authorization import (
    find_unavailable_secrets,
)


def test_masked_nested_secrets_are_rejected() -> None:
    missing = find_unavailable_secrets(
        {
            "auth": {"password": "********"},
            "rules": [{"psk": "real-value"}, {"psk": None}],
        },
        frozenset({"password", "psk"}),
    )

    assert missing == {"auth.password", "rules.1.psk"}


def test_non_secret_masked_values_are_allowed() -> None:
    assert not find_unavailable_secrets(
        {"description": "********"},
        frozenset({"password"}),
    )
