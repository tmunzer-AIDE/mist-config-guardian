"""Restore authorization safety checks."""

from mist_config_guardian_backend.services.restore_authorization import (
    find_unavailable_secrets,
    format_secret_path,
)


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
