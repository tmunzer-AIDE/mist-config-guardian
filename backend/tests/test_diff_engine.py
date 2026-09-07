"""Deterministic configuration diff engine tests."""

import json

from mist_config_guardian_backend.schemas.diff import DIFF_SECRET_MASK, DiffChangeKind
from mist_config_guardian_backend.services.diff import (
    build_json_patch,
    count_document_lines,
    diff_configurations,
    section_label,
)


def _entries(diff) -> dict[str, object]:
    collected = {}
    for section in diff.sections:
        for entry in section.entries:
            collected[entry.field] = entry
    return collected


def test_nested_add_modify_and_remove_are_classified() -> None:
    before = {
        "name": "NW-Corp",
        "band_5": {"power_max": 17, "channels": [36, 40]},
        "legacy": {"enabled": True},
    }
    after = {
        "name": "NW-Corp",
        "band_5": {"power_max": 11, "channels": [36, 40], "min_power": 8},
        "guest": {"vlan": 310},
    }

    diff = diff_configurations(before, after)
    entries = _entries(diff)

    assert entries["band_5.power_max"].kind is DiffChangeKind.MODIFIED
    assert entries["band_5.power_max"].before == "17"
    assert entries["band_5.power_max"].after == "11"
    assert entries["band_5.min_power"].kind is DiffChangeKind.ADDED
    assert entries["legacy.enabled"].kind is DiffChangeKind.REMOVED
    assert entries["guest.vlan"].kind is DiffChangeKind.ADDED
    assert "name" not in entries
    assert diff.counts.changed == 4
    assert diff.counts.added == 2
    assert diff.counts.modified == 1
    assert diff.counts.removed == 1
    assert diff.summary == "4 fields changed · 2 added · 1 modified · 1 removed"
    assert diff.mode == "chips"
    assert len(diff.entries) == 4


def test_positional_list_paths_use_bracketed_indices() -> None:
    before = {"auth_servers": [{"host": "10.0.0.1", "port": 1812}]}
    after = {"auth_servers": [{"host": "10.0.0.9", "port": 1812}]}

    entries = _entries(diff_configurations(before, after))

    assert "auth_servers[0].host" in entries
    assert entries["auth_servers[0].host"].after == "10.0.0.9"


def test_identity_keyed_lists_match_by_name_not_position() -> None:
    before = {
        "networks": [
            {"name": "corp-data", "subnet": "10.10.0.0/22"},
            {"name": "corp-voice", "vlan": 220},
        ]
    }
    after = {
        "networks": [
            {"name": "corp-voice", "vlan": 220},
            {"name": "corp-data", "subnet": "10.10.0.0/20"},
        ]
    }

    diff = diff_configurations(before, after)
    entries = _entries(diff)

    assert "networks[corp-data].subnet" in entries
    assert entries["networks[corp-data].subnet"].after == "10.10.0.0/20"
    assert entries["networks"].reordered is True
    assert diff.counts.changed == 2


def test_pure_reorder_is_reported_once() -> None:
    before = {"networks": [{"name": "a", "vlan": 1}, {"name": "b", "vlan": 2}]}
    after = {"networks": [{"name": "b", "vlan": 2}, {"name": "a", "vlan": 1}]}

    diff = diff_configurations(before, after)

    assert diff.counts.changed == 1
    entry = diff.entries[0]
    assert entry.field == "networks"
    assert entry.reordered is True
    assert entry.kind is DiffChangeKind.MODIFIED
    assert entry.before == "a, b"
    assert entry.after == "b, a"
    assert "reordered" in entry.note


def test_scalar_list_reorder_is_reported_once() -> None:
    diff = diff_configurations(
        {"band_5": {"channels": [36, 40, 44]}},
        {"band_5": {"channels": [44, 36, 40]}},
    )

    assert diff.counts.changed == 1
    assert diff.entries[0].field == "band_5.channels"
    assert diff.entries[0].reordered is True


def test_identity_keyed_removal_and_addition() -> None:
    before = {"networks": [{"name": "corp-voice", "vlan": 220}]}
    after = {"networks": [{"name": "guest-wifi", "vlan": 310}]}

    entries = _entries(diff_configurations(before, after))

    assert entries["networks[corp-voice].name"].kind is DiffChangeKind.REMOVED
    assert entries["networks[corp-voice].vlan"].kind is DiffChangeKind.REMOVED
    assert entries["networks[guest-wifi].vlan"].kind is DiffChangeKind.ADDED


def test_sections_are_labelled_and_notable_sections_come_first() -> None:
    before = {"description": "old", "band_5": {"power_max": 17}, "auth_servers": [{"host": "a"}]}
    after = {"description": "new", "band_5": {"power_max": 11}, "auth_servers": [{"host": "b"}]}

    diff = diff_configurations(before, after)
    names = [section.name for section in diff.sections]
    keys = [section.key for section in diff.sections]

    assert names[: len(names) - 1] == ["Auth servers", "Band 5 GHz"]
    assert keys[-1] == "description"
    assert diff.sections[0].notable == 1
    assert diff.sections[0].path == "auth_servers[]"
    assert diff.sections[1].path == "band_5{}"
    assert diff.sections[0].detail == "1 modified"


def test_section_label_expands_known_keys_and_acronyms() -> None:
    assert section_label("band_5") == "Band 5 GHz"
    assert section_label("auth_servers") == "Auth servers"
    assert section_label("bgp_config") == "BGP config"
    assert section_label("port_config") == "Port config"


def test_notable_rules_flag_security_topology_radio_and_removals() -> None:
    before = {
        "radius_servers": [{"host": "10.0.0.1"}],
        "networks": {"corp": {"subnet": "10.0.0.0/24"}},
        "rf_template_id": "indoor-std",
        "description": "old",
        "notes": "kept",
    }
    after = {
        "radius_servers": [{"host": "10.0.0.2"}],
        "networks": {"corp": {"subnet": "10.0.0.0/20"}},
        "rf_template_id": "indoor-dense",
        "description": "new",
    }

    diff = diff_configurations(before, after)
    entries = _entries(diff)

    assert entries["radius_servers[0].host"].notable is True
    assert "Security-relevant" in entries["radius_servers[0].host"].note
    assert entries["networks.corp.subnet"].notable is True
    assert "Topology" in entries["networks.corp.subnet"].note
    assert entries["rf_template_id"].notable is True
    assert "Radio" in entries["rf_template_id"].note
    assert entries["description"].notable is False
    assert entries["notes"].notable is True
    assert entries["notes"].kind is DiffChangeKind.REMOVED
    assert next(entry.field for entry in diff.notable) == "notes"


def test_notes_are_deterministic_and_factual() -> None:
    diff = diff_configurations({"band_steer": False}, {"band_steer": True})

    entry = diff.entries[0]
    assert entry.note.startswith("band_steer changed from false to true.")
    assert diff_configurations({"band_steer": False}, {"band_steer": True}).entries[0].note == entry.note


def test_masked_secret_never_leaks_and_equal_ciphertext_is_not_a_change() -> None:
    before = {"radius": {"secret": {"$encrypted": "v1:aaa"}, "host": "10.0.0.1"}}
    same = {"radius": {"secret": {"$encrypted": "v1:aaa"}, "host": "10.0.0.1"}}
    changed = {"radius": {"secret": {"$encrypted": "v1:bbb"}, "host": "10.0.0.1"}}

    assert diff_configurations(before, same).counts.changed == 0

    diff = diff_configurations(before, changed)
    entry = diff.entries[0]
    assert entry.field == "radius.secret"
    assert entry.kind is DiffChangeKind.MODIFIED
    assert entry.secret is True
    assert entry.secret_unknown is True
    assert entry.before == DIFF_SECRET_MASK
    assert entry.after == DIFF_SECRET_MASK
    assert diff.secret_fields == 1
    payload = diff.model_dump_json()
    assert "v1:aaa" not in payload
    assert "v1:bbb" not in payload
    assert "$encrypted" not in payload


def test_secret_fingerprints_decide_equality_without_guessing() -> None:
    before = {"psk": {"$encrypted": "v1:aaa", "$fingerprint": "sha256:1"}}
    rotated_ciphertext = {"psk": {"$encrypted": "v1:zzz", "$fingerprint": "sha256:1"}}
    rotated_value = {"psk": {"$encrypted": "v1:zzz", "$fingerprint": "sha256:2"}}

    assert diff_configurations(before, rotated_ciphertext).counts.changed == 0

    diff = diff_configurations(before, rotated_value)
    assert diff.counts.changed == 1
    assert diff.entries[0].secret is True
    assert diff.entries[0].secret_unknown is False
    assert "sha256:1" not in diff.model_dump_json()


def test_added_and_removed_secrets_are_masked() -> None:
    diff = diff_configurations({}, {"wlan": {"psk": {"$encrypted": "v1:new"}}})

    entry = diff.entries[0]
    assert entry.field == "wlan.psk"
    assert entry.kind is DiffChangeKind.ADDED
    assert entry.secret is True
    assert entry.before is None
    assert entry.after == DIFF_SECRET_MASK
    assert "v1:new" not in diff.model_dump_json()


def test_large_diff_switches_to_sections_and_supports_metadata_only() -> None:
    before = {"band_5": {f"key_{index}": index for index in range(12)}, "description": "old"}
    after = {"band_5": {f"key_{index}": index + 1 for index in range(12)}, "description": "new"}

    diff = diff_configurations(before, after)
    assert diff.mode == "sections"
    assert diff.entries == []
    assert diff.counts.changed == 13

    metadata = diff_configurations(before, after, include_entries=False)
    assert metadata.entries_included is False
    assert metadata.notable == []
    assert metadata.counts.changed == 13
    assert [section.counts.changed for section in metadata.sections] == [12, 1]
    assert all(section.entries == [] for section in metadata.sections)
    assert all(section.entries_included is False for section in metadata.sections)


def test_section_filter_returns_only_requested_bodies() -> None:
    before = {"band_5": {"power_max": 17}, "description": "old"}
    after = {"band_5": {"power_max": 11}, "description": "new"}

    diff = diff_configurations(before, after, sections=["band_5"])
    by_key = {section.key: section for section in diff.sections}

    assert by_key["band_5"].entries_included is True
    assert len(by_key["band_5"].entries) == 1
    assert by_key["description"].entries_included is False
    assert by_key["description"].entries == []
    assert by_key["description"].counts.changed == 1


def test_max_entries_marks_the_diff_truncated_without_losing_counts() -> None:
    before = {"band_5": {f"key_{index}": index for index in range(20)}}
    after = {"band_5": {f"key_{index}": index + 1 for index in range(20)}}

    diff = diff_configurations(before, after, max_entries=5)

    assert diff.truncated is True
    assert diff.counts.changed == 20
    assert sum(len(section.entries) for section in diff.sections) == 5


def test_json_patch_export_is_rfc6902_and_redacted() -> None:
    before = {
        "name": "NW-Corp",
        "psk": {"$encrypted": "v1:aaa"},
        "channels": [36, 40, 44],
        "legacy": True,
    }
    after = {
        "name": "NW-Corp-2",
        "psk": {"$encrypted": "v1:bbb"},
        "channels": [36, 40],
        "guest": {"vlan": 310},
    }

    patch = build_json_patch(before, after)
    serialized = json.dumps(patch)

    assert {"op": "replace", "path": "/name", "value": "NW-Corp-2"} in patch
    assert {"op": "remove", "path": "/legacy"} in patch
    assert {"op": "add", "path": "/guest", "value": {"vlan": 310}} in patch
    assert {"op": "remove", "path": "/channels/2"} in patch
    assert "v1:aaa" not in serialized
    assert "v1:bbb" not in serialized


def test_json_patch_escapes_pointer_segments_and_appends_list_items() -> None:
    patch = build_json_patch({"a/b": 1, "items": [1]}, {"a/b": 2, "items": [1, 2]})

    assert {"op": "replace", "path": "/a~1b", "value": 2} in patch
    assert {"op": "add", "path": "/items/-", "value": 2} in patch


def test_line_count_uses_the_taller_document() -> None:
    assert count_document_lines({"a": 1}, {"a": 1, "b": {"c": 2}}) == 6
