"""Guardian's change model: paths from the diff walker, stable atoms, segment-aware prefixes and a masked view."""

import dataclasses
import itertools

import pytest

from mist_config_guardian_backend.guardian.change import (
    CHANGE_VIEW_CHANGES_PER_ATOM,
    ObjectChange,
    build_change_set,
    change_view,
    covers,
)
from mist_config_guardian_backend.guardian.contracts import ChangeAtom
from mist_config_guardian_backend.guardian.evidence import CHANGE_VIEW_BUDGET, json_size
from mist_config_guardian_backend.services.diff import COMPARISON_IGNORED_FIELDS, diff_configurations
from mist_config_guardian_backend.snapshots.diffing import MAX_ENTRIES, changed_entries, changed_paths
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS

SECRET = {"$encrypted": "ciphertext-one", "$fingerprint": "fingerprint-one"}
ROTATED = {"$encrypted": "ciphertext-two", "$fingerprint": "fingerprint-two"}
REENCRYPTED = {"$encrypted": "ciphertext-three", "$fingerprint": "fingerprint-one"}
TEMPLATE_ID = "00000000000000000000c001"
MAC = "020000000011"
SITE = "20000000-0000-4000-8000-000000000001"


def template(before: dict[str, object], after: dict[str, object], **overrides: object) -> ObjectChange:
    values: dict[str, object] = {
        "logical_object_id": TEMPLATE_ID,
        "scope": "org",
        "object_type": "networktemplates",
        "name": "DNT-NTR",
        "version": 7,
        "before": before,
        "after": after,
    }
    return ObjectChange(**(values | overrides))


@pytest.mark.parametrize(
    ("before", "after", "paths"),
    [
        pytest.param({"vlan": 1}, {"vlan": 2}, [("vlan",)], id="scalar"),
        pytest.param({"a": {"b": 1}}, {"a": {"b": 2, "c": 3}}, [("a", "b"), ("a", "c")], id="nested add and modify"),
        pytest.param(
            {"gone": {"x": 1, "y": [1, 2]}},
            {},
            [("gone", "x"), ("gone", "y", "0"), ("gone", "y", "1")],
            id="removed subtree leaves",
        ),
        pytest.param({"dns_servers": ["10.0.0.1"]}, {"dns_servers": ["10.0.0.2"]}, [("dns_servers", "0")], id="item"),
        pytest.param({"dns_servers": ["a", "b"]}, {"dns_servers": ["b", "a"]}, [("dns_servers",)], id="pure reorder"),
        pytest.param(
            {"port_config": [{"port_id": "ge-0/0/1", "disabled": False}]},
            {"port_config": [{"port_id": "ge-0/0/1", "disabled": True}]},
            [("port_config", "ge-0/0/1", "disabled")],
            id="identity-keyed item",
        ),
        pytest.param({"a.b": 1, "c[0]": 1}, {"a.b": 2, "c[0]": 2}, [("a.b",), ("c[0]",)], id="punctuation in a key"),
        pytest.param({"auth": {"psk": SECRET}}, {"auth": {"psk": ROTATED}}, [("auth", "psk")], id="rotated secret"),
        pytest.param({"auth": {"psk": SECRET}}, {"auth": {"psk": REENCRYPTED}}, [], id="re-encrypted secret"),
        pytest.param({"psk": {"$encrypted": "one"}}, {"psk": {"$encrypted": "two"}}, [("psk",)], id="uncomparable"),
        pytest.param(
            {"modified_time": 1, "created_time": 1, "last_seen": 1, "nested": [{"modified_time": 1, "vlan": 1}]},
            {"modified_time": 2, "created_time": 2, "last_seen": 2, "nested": [{"modified_time": 2, "vlan": 1}]},
            [],
            id="metadata at any depth",
        ),
    ],
)
def test_changed_paths_are_segment_tuples(before, after, paths):
    result = changed_paths(before, after, DEFAULT_IGNORED_FIELDS)

    assert sorted(result.paths) == sorted(paths)
    assert result.complete


def test_changed_paths_carry_no_values():
    result = changed_paths(
        {"ssid": "Corp-old", "auth": {"psk": SECRET}}, {"ssid": "Corp-new", "auth": {"psk": ROTATED}}, ()
    )

    assert [field.name for field in dataclasses.fields(result)] == ["paths", "complete"]
    assert all(isinstance(segment, str) for path in result.paths for segment in path)
    for value in ("Corp-old", "Corp-new", "ciphertext", "fingerprint", "********"):
        assert value not in repr(result)


def test_changed_paths_come_from_the_visible_diff_walker():
    before = {"networks": [{"name": "a", "vlan": 1}, {"name": "b", "vlan": 2}], "band_5": {"channels": [36, 40]}}
    after = {"networks": [{"name": "b", "vlan": 3}, {"name": "a", "vlan": 1}], "band_5": {"channels": [40, 36]}}

    diff = diff_configurations(before, after)
    located = changed_entries(before, after, COMPARISON_IGNORED_FIELDS)

    assert sorted(entry.field for entry in diff.entries) == sorted(entry.field for _, entry in located)
    assert [path for path, _ in located] == list(changed_paths(before, after, COMPARISON_IGNORED_FIELDS).paths)
    assert {entry.field: path for path, entry in located} == {
        "networks": ("networks",),
        "networks[b].vlan": ("networks", "b", "vlan"),
        "band_5.channels": ("band_5", "channels"),
    }


@pytest.mark.parametrize(("changes", "complete"), [(MAX_ENTRIES, True), (MAX_ENTRIES + 1, False)])
def test_the_walker_cap_decides_completeness(changes, complete):
    result = changed_paths({"items": dict.fromkeys(map(str, range(changes)), 0)}, {"items": {}}, ())

    assert len(result.paths) == min(changes, MAX_ENTRIES)
    assert result.complete is complete


@pytest.mark.parametrize(
    ("prefix", "path", "covered"),
    [
        (("port_config",), ("port_config", "ge-0/0/1", "disabled"), True),
        (("port_config", "ge-0/0/1"), ("port_config", "ge-0/0/1", "disabled"), True),
        (("port_config", "ge-0/0/1", "disabled"), ("port_config", "ge-0/0/1", "disabled"), True),
        (("ports", "1"), ("ports", "10"), False),
        (("ports", "1"), ("ports", "1", "poe_disabled"), True),
        (("port",), ("port_config", "ge-0/0/1"), False),
        (("port_config", "ge-0/0/1", "disabled"), ("port_config", "ge-0/0/1"), False),
        (("a.b",), ("a", "b"), False),
        (("a",), ("a.b",), False),
    ],
)
def test_prefix_coverage_compares_whole_segments(prefix, path, covered):
    assert covers(prefix, path) is covered


def test_the_dnt_ntr_template_edit_is_one_dns_atom_without_metadata():
    change = build_change_set(
        [
            template(
                {"name": "DNT-NTR", "dns_servers": ["10.0.0.1"], "modified_time": 1},
                {"name": "DNT-NTR", "dns_servers": ["10.0.0.2", "10.0.0.3"], "modified_time": 2},
            )
        ]
    )

    assert change.atoms == (
        ChangeAtom(
            id="A1",
            logical_object_id=TEMPLATE_ID,
            version=7,
            attribute="dns_servers",
            paths=(("dns_servers", "0"), ("dns_servers", "1")),
            paths_complete=True,
        ),
    )
    assert change.object_of(change.atoms[0]).object_type == "networktemplates"


def test_atom_ids_are_stable_whatever_the_input_order():
    changes = [
        template({"b": 1, "a": 1}, {"b": 2, "a": 2}, logical_object_id="obj-b"),
        template({"z": 1}, {"z": 2}, logical_object_id="obj-a", version=3),
        template({"y": 1}, {"y": 2}, logical_object_id="obj-a", version=2),
        template({}, {"device": "x"}, logical_object_id="obj-c", scope="site", object_type="devices", site_id=SITE),
    ]
    expected = build_change_set(changes)

    for ordering in itertools.permutations(changes):
        assert build_change_set(ordering) == expected
    assert [(atom.id, atom.logical_object_id, atom.version, atom.attribute) for atom in expected.atoms] == [
        ("A1", "obj-a", 2, "y"),
        ("A2", "obj-a", 3, "z"),
        ("A3", "obj-b", 7, "a"),
        ("A4", "obj-b", 7, "b"),
        ("A5", "obj-c", 7, "device"),
    ]


def test_a_device_object_keeps_its_identity_for_targeting():
    change = build_change_set(
        [
            template(
                {"port_config": {"ge-0/0/1": {"disabled": False}}},
                {"port_config": {"ge-0/0/1": {"disabled": True}}},
                scope="site",
                object_type="devices",
                name="SW-1",
                site_id=SITE,
                device_mac=MAC,
            )
        ]
    )

    changed = change.object_of(change.atoms[0])
    assert (changed.scope, changed.site_id, changed.device_mac) == ("site", SITE, MAC)


def test_a_truncated_object_leaves_every_atom_incomplete_and_still_names_attributes_past_the_cap():
    before = {"a": dict.fromkeys(map(str, range(MAX_ENTRIES)), 0), "z": 0}
    after = {"a": dict.fromkeys(map(str, range(MAX_ENTRIES)), 1), "z": 1}

    atoms = build_change_set([template(before, after)]).atoms

    assert [(atom.attribute, len(atom.paths), atom.paths_complete) for atom in atoms] == [
        ("a", MAX_ENTRIES, False),
        ("z", 1, False),
    ]
    assert atoms[1].paths == (("z",),)


def test_a_segment_too_long_to_name_is_represented_by_its_parent():
    key = "ge-0/0/1," * 20
    change = build_change_set([template({"port_config": {key: {"disabled": False}}}, {"port_config": {}})])

    assert change.atoms[0].paths == (("port_config",),)


def test_an_attribute_that_cannot_be_named_is_refused():
    with pytest.raises(ValueError, match="attribute"):
        build_change_set([template({"x" * 129: 1}, {"x" * 129: 2})])


def test_one_object_version_appears_once():
    with pytest.raises(ValueError, match="once"):
        build_change_set([template({"a": 1}, {"a": 2}), template({"b": 1}, {"b": 2})])


def test_values_reach_only_the_masked_view():
    change = build_change_set(
        [
            template(
                {"ssid": "Corp-old", "auth": {"psk": SECRET}, "modified_time": 1},
                {"ssid": "Corp-new", "auth": {"psk": ROTATED}, "modified_time": 2},
                object_type="wlans",
            )
        ]
    )
    view = change_view(change)
    changes = {item.attribute: item.changes for item in view.items}

    for value in ("Corp-old", "Corp-new", "ciphertext", "fingerprint"):
        assert value not in repr(change.atoms)
    for value in ("ciphertext", "fingerprint"):
        assert value not in view.model_dump_json()
    assert [(c.path, c.kind, c.before, c.after) for c in changes["auth"]] == [
        ("auth.psk", "modified", "********", "********")
    ]
    assert [(c.path, c.kind, c.before, c.after) for c in changes["ssid"]] == [
        ("ssid", "modified", "Corp-old", "Corp-new")
    ]


def test_the_change_view_fits_its_budget_in_atom_order_and_counts_what_it_left_out():
    long_value = "v" * 400
    before = {f"attribute_{index:03}": [long_value] * 10 for index in range(60)}
    after = {f"attribute_{index:03}": [f"{long_value}-new"] * 10 for index in range(60)}
    change = build_change_set([template(before, after)])

    view = change_view(change)

    assert json_size(view) <= CHANGE_VIEW_BUDGET
    assert [item.id for item in view.items] == [atom.id for atom in change.atoms[: len(view.items)]]
    assert 0 < len(view.items) < len(change.atoms)
    assert view.omitted == {"networktemplates": len(change.atoms) - len(view.items)}
    for item in view.items:
        assert item.path_count == 10
        assert len(item.changes) == CHANGE_VIEW_CHANGES_PER_ATOM
        assert all(len(c.before or "") <= 120 for c in item.changes)
