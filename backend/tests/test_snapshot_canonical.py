"""Snapshot canonicalization tests."""

import hashlib
import json

from mist_config_guardian_backend.snapshots.canonical import (
    CURRENT_HASH_GENERATION,
    canonicalize,
    changed_top_level_fields,
    configuration_hash,
    configuration_hash_matches,
    is_legacy_hash,
    legacy_configuration_hash,
)

_WLAN = {"name": "NW-Corp", "psk": "correct-horse-battery-staple", "vlan": 12}


def test_hash_is_independent_of_mapping_key_order() -> None:
    left = {"name": "WLAN", "settings": {"vlan": 12, "enabled": True}}
    right = {"settings": {"enabled": True, "vlan": 12}, "name": "WLAN"}

    assert configuration_hash(left) == configuration_hash(right)


def test_hash_preserves_list_order() -> None:
    assert configuration_hash({"rules": ["first", "second"]}) != configuration_hash({"rules": ["second", "first"]})


def test_ignored_fields_are_removed_recursively() -> None:
    result = canonicalize(
        {"modified_time": 1, "nested": {"modified_time": 2, "value": 3}},
        ignored_fields={"modified_time"},
    )

    assert result == {"nested": {"value": 3}}


def test_changed_fields_are_sorted() -> None:
    assert changed_top_level_fields(
        {"z": 1, "same": {"b": 2, "a": 1}},
        {"a": 2, "same": {"a": 1, "b": 2}},
    ) == ["a", "z"]


def test_the_digest_cannot_be_reproduced_from_the_configuration_alone() -> None:
    """The whole point of keying it: knowing the plaintext is not enough.

    A viewer holds everything but the secret, so an unkeyed digest published
    beside a redacted configuration confirms a guessed secret in one hash. This
    one cannot be recomputed without the key, which the API never gives out.
    """
    unkeyed = hashlib.sha256(json.dumps(_WLAN, separators=(",", ":"), sort_keys=True).encode()).hexdigest()

    assert configuration_hash(_WLAN) != unkeyed
    assert unkeyed not in configuration_hash(_WLAN)


def test_the_digest_says_which_generation_it_belongs_to() -> None:
    assert configuration_hash(_WLAN).startswith(f"{CURRENT_HASH_GENERATION}:")
    assert not is_legacy_hash(configuration_hash(_WLAN))
    assert is_legacy_hash(legacy_configuration_hash(_WLAN))


def test_a_stored_digest_of_either_generation_still_recognises_its_configuration() -> None:
    """Nothing stored before the key existed stops being readable."""
    changed = {**_WLAN, "vlan": 13}

    for stored in (legacy_configuration_hash(_WLAN), configuration_hash(_WLAN)):
        assert configuration_hash_matches(stored, _WLAN)
        assert not configuration_hash_matches(stored, changed)


def test_matching_applies_the_ignored_fields_it_is_given() -> None:
    stored = legacy_configuration_hash(_WLAN, ignored_fields={"modified_time"})
    touched = {**_WLAN, "modified_time": 99}

    assert configuration_hash_matches(stored, touched, ignored_fields={"modified_time"})
    assert not configuration_hash_matches(stored, touched)


def test_a_missing_digest_describes_nothing() -> None:
    assert not configuration_hash_matches(None, _WLAN)
