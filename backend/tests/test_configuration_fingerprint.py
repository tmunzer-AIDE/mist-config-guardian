"""One normalization for backup, baseline, compensation, executor and verification."""

import pytest

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.snapshots import canonical
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.fingerprint import (
    MISSING,
    at_path,
    differing_fields,
    equivalent,
    fingerprint,
    fingerprint_matches,
    normalize,
    restored_configuration,
    without_paths,
)
from mist_config_guardian_backend.snapshots.registry import get_definition

WLANS = get_definition("site", "wlans")
MAPS = get_definition("site", "maps")
assert WLANS is not None
assert MAPS is not None


def test_normalize_drops_server_managed_and_read_only_fields() -> None:
    first = {"name": "Floor 1", "url": "https://generated.example/a", "modified_time": 1}
    second = {"name": "Floor 1", "url": "https://generated.example/b", "modified_time": 2}

    assert normalize(MAPS, first) == normalize(MAPS, second)
    assert fingerprint(MAPS, first) == fingerprint(MAPS, second)
    assert fingerprint(MAPS, first) == configuration_hash(first, ignored_fields=MAPS.ignored_fields)


def test_fingerprint_matches_a_digest_the_collector_stored() -> None:
    live = {"id": "wlan-1", "ssid": "Corp", "modified_time": 5}

    assert fingerprint_matches(WLANS, configuration_hash(live, ignored_fields=WLANS.ignored_fields), live)


def test_equivalence_tolerates_a_mask_where_a_secret_was_written() -> None:
    written = {"ssid": "Corp", "psk": "correct-horse"}
    live = {"id": "wlan-1", "ssid": "Corp", "psk": "********", "modified_time": 5}

    assert equivalent(WLANS, written, live, fields=written.keys())


def test_equivalence_still_sees_a_changed_secret_and_names_the_field() -> None:
    written = {"ssid": "Corp", "psk": "correct-horse", "vlan_id": 10}
    live = {"ssid": "Corp", "psk": "battery-staple", "vlan_id": 11}

    assert differing_fields(WLANS, written, live, fields=written.keys()) == ["psk", "vlan_id"]


def test_a_field_present_on_one_side_only_differs() -> None:
    assert differing_fields(WLANS, {"ssid": "Corp"}, {"ssid": "Corp", "vlan_id": None}) == ["vlan_id"]
    assert not equivalent(WLANS, {"ssid": "Corp", "vlan_id": 1}, {"ssid": "Corp"})


def test_a_mask_over_one_secret_does_not_hide_a_change_to_another_of_the_same_name() -> None:
    written = {"auth": {"psk": "primary"}, "backup": {"psk": "old-backup"}}
    live = {"auth": {"psk": "********"}, "backup": {"psk": "rotated-backup"}}

    assert differing_fields(WLANS, written, live) == ["backup"]


def test_a_restored_configuration_keeps_the_secret_mist_masked() -> None:
    readback = {"id": "wlan-1", "ssid": "Corp", "auth": {"psk": "********"}}

    restored = restored_configuration(WLANS, readback, {"ssid": "Corp", "auth": {"psk": "correct-horse"}})

    assert restored == {"id": "wlan-1", "ssid": "Corp", "auth": {"psk": "correct-horse"}}
    assert readback["auth"] == {"psk": "********"}


def test_a_restored_configuration_keeps_a_mask_nothing_written_can_fill() -> None:
    readback = {"ssid": "Corp", "keys": [{"psk": "********"}, {"psk": "********"}]}

    restored = restored_configuration(WLANS, readback, {"keys": [{"psk": "first"}, {"psk": "****"}]})

    assert restored == {"ssid": "Corp", "keys": [{"psk": "first"}, {"psk": "********"}]}


def test_paths_are_read_and_dropped_step_for_step() -> None:
    value = {"a.b": {"0": {"psk": "dotted"}}, "a": {"b": [{"psk": "listed", "ssid": "Corp"}]}}

    assert at_path(value, ("a", "b", 0, "psk")) == "listed"
    assert at_path(value, ("a.b", 0, "psk")) is MISSING
    assert without_paths(value, frozenset({("a", "b", 0, "psk")})) == {
        "a.b": {"0": {"psk": "dotted"}},
        "a": {"b": [{"ssid": "Corp"}]},
    }


# Digests the collector stored for these responses before this module existed,
# under a pinned key. Every stored version is compared against digests like
# these, so if they moved, every organization would record a spurious change
# on its next backup.
_COLLECTED_WLAN = {
    "id": "7c1b8f2e-0000-4000-8000-000000000001",
    "ssid": "Corp",
    "enabled": True,
    "vlan_id": 10,
    "auth": {"type": "psk", "psk": "********"},
    "portal_template_url": "https://generated.example/t",
    "rules": [{"dst": "10.0.0.0/8", "note": "café"}, {"dst": "any", "modified_time": 3}],
    "created_time": 1,
    "modified_time": 2,
}
_COLLECTED_WLAN_DIGEST = "v2:e5795d25c4ffa7497ef0f326711c3f992c4e0b643338b59c42c927315756cff7"
_COLLECTED_MAP = {
    "id": "7c1b8f2e-0000-4000-8000-000000000002",
    "name": "Floor 1",
    "url": "https://generated.example/a",
    "thumbnail_url": "https://generated.example/b",
    "width": 1200,
    "modified_time": 5,
}
_COLLECTED_MAP_DIGEST = "v2:b63bd779c4057348dff17091605cfe651e3d75cd9ff015623ed896e3daeff33f"


@pytest.fixture
def pinned_hash_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        canonical, "get_settings", lambda: Settings(environment="test", credential_encryption_key="test-key")
    )


@pytest.mark.usefixtures("pinned_hash_key")
def test_the_collector_digest_of_an_unchanged_response_is_byte_identical() -> None:
    assert fingerprint(WLANS, _COLLECTED_WLAN) == _COLLECTED_WLAN_DIGEST
    assert fingerprint(MAPS, _COLLECTED_MAP) == _COLLECTED_MAP_DIGEST
    assert fingerprint_matches(WLANS, _COLLECTED_WLAN_DIGEST, {**_COLLECTED_WLAN, "modified_time": 99})
