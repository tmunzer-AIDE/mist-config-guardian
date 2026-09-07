"""Snapshot canonicalization tests."""

from mist_config_guardian_backend.snapshots.canonical import (
    canonicalize,
    changed_top_level_fields,
    configuration_hash,
)


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
