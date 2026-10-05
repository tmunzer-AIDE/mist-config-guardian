"""Digital-twin applicability is reused as bounded Guardian agent guidance."""

import pytest

from mist_config_guardian_backend.guardian.change import ChangeSet, ObjectChange, build_change_set
from mist_config_guardian_backend.guardian.impact_rules import agent_hints, candidate_rules


def change(object_type: str, before: dict, after: dict, *, scope: str = "site") -> ChangeSet:
    return build_change_set(
        [
            ObjectChange(
                logical_object_id="object-1",
                scope=scope,
                object_type=object_type,
                name="Changed object",
                version=2,
                before=before,
                after=after,
                site_id="site-1" if scope == "site" else None,
            )
        ]
    )


def ids(value: ChangeSet) -> set[str]:
    return {rule.id for rule in candidate_rules(value)}


def test_port_change_selects_topology_power_auth_and_client_checks() -> None:
    selected = ids(
        change(
            "devices",
            {"port_config": {"ge-0/0/1": {"disabled": False}}},
            {"port_config": {"ge-0/0/1": {"disabled": True}}},
        )
    )

    assert {
        "wired.l2.blackhole",
        "wired.poe.disconnect",
        "wired.port.admin_disable",
        "wired.auth.access_change",
        "wired.client.impact",
        "wired.auth.radius_missing",
        "wired.l3.control_plane_reachability",
        "wired.port.storm_control_policy",
    } <= selected
    assert "wired.l3.bgp_adjacency" not in selected
    assert "wireless.wlan.client_impact" not in selected


def test_bgp_change_selects_only_the_bgp_check() -> None:
    selected = ids(
        change(
            "settings",
            {"bgp_config": {"default": {"local_as": 64512}}},
            {"bgp_config": {"default": {"local_as": 64513}}},
        )
    )

    assert selected == {"wired.l3.bgp_adjacency"}


def test_wlan_change_selects_the_three_wireless_checks() -> None:
    selected = ids(change("wlans", {"enabled": True}, {"enabled": False}))

    assert selected == {
        "wireless.wlan.client_impact",
        "wireless.wlan.open_guest",
        "wireless.wlan.duplicate_ssid",
    }


def test_nac_change_selects_delta_and_shadowing_checks() -> None:
    selected = ids(change("nacrules", {"order": 2}, {"order": 1}, scope="org"))

    assert selected == {"nac.rule.change", "nac.rule.shadowed"}


def test_cosmetic_device_change_does_not_invent_an_impact_rule() -> None:
    assert candidate_rules(change("devices", {"notes": "old"}, {"notes": "new"})) == ()


def test_hints_are_chunked_and_labelled_as_candidates_not_findings() -> None:
    hints = agent_hints(change("networktemplates", {"vars": {"vlan": 10}}, {"vars": {"vlan": 20}}, scope="org"))

    assert hints
    assert all(len(value) <= 440 for value in hints.values())
    assert "not findings" in hints["impact-rules-1"]
    assert "wired.l2.blackhole" in " ".join(hints.values())
    assert "wired.l3.bgp_adjacency" in " ".join(hints.values())


@pytest.mark.parametrize("root", ["radius_config", "mist_nac"])
@pytest.mark.parametrize("kind", ["devices", "networktemplates", "switchprofiles"])
def test_backend_edits_request_admission_verification(root: str, kind: str) -> None:
    selected = ids(change(kind, {root: {"enabled": False}}, {root: {"enabled": True}}))

    assert "wired.auth.radius_missing" in selected
    assert "wireless.wlan.client_impact" not in selected


@pytest.mark.parametrize("root", ["extra_routes", "extra_routes6"])
def test_static_route_edits_request_forwarding_and_control_plane_verification(root: str) -> None:
    selected = ids(change("devices", {root: {"default": {"via": "old"}}}, {root: {}}))

    assert selected == {"wired.l3.static_route_reachability", "wired.l3.control_plane_reachability"}


def test_interface_edit_requests_topology_and_route_dependency_checks() -> None:
    selected = ids(change("devices", {"other_ip_configs": {"vlan10": {"ip": "old"}}}, {"other_ip_configs": {}}))

    assert {
        "wired.l2.topology_coverage",
        "wired.l3.static_route_reachability",
        "wired.l3.control_plane_reachability",
    } <= selected


@pytest.mark.parametrize("kind", ["wlans", "templates"])
def test_wlan_vlan_edits_are_not_silently_omitted(kind: str) -> None:
    selected = ids(change(kind, {"vlan_id": 10}, {"vlan_id": 20}))

    assert "wireless.wlan.client_impact" in selected


def test_inherited_port_profile_edits_include_storm_control() -> None:
    selected = ids(
        change(
            "switchprofiles",
            {"port_usages": {"uplink": {"storm_control": {"disable_port": False}}}},
            {"port_usages": {"uplink": {"storm_control": {"disable_port": True}}}},
        )
    )

    assert "wired.port.storm_control_policy" in selected


def test_org_network_change_requests_site_topology_and_l3_verification() -> None:
    selected = ids(change("networks", {"vlan_id": 10}, {"vlan_id": 20}, scope="org"))

    assert {"wired.l2.blackhole", "wired.l3.static_route_reachability"} <= selected


@pytest.mark.parametrize(
    "kind",
    ["assetfilters", "assets", "zones", "rssizones", "alarmtemplates", "webhooks", "ssos", "ssoroles", "unknown"],
)
def test_non_network_or_unsupported_objects_have_no_candidates(kind: str) -> None:
    assert agent_hints(change(kind, {"name": "old"}, {"name": "new"})) == {}


def test_template_assignment_change_requests_site_forwarding_checks() -> None:
    selected = ids(change("sites", {"networktemplate_id": "old"}, {"networktemplate_id": "new"}, scope="org"))

    assert {"wired.l2.blackhole", "wired.auth.radius_missing", "wired.port.storm_control_policy"} <= selected
