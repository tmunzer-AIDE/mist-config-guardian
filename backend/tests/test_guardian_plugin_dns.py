"""The dns plug-in: only the Task 1 verified mappings, the dual-use union, and nothing invented.

The table in ``src`` is held to the frozen fixture row for row, so neither can drift without the other.
"""

import pytest

from guardian_verification import DNS_SEMANTICS_FIXTURE, load_fixture
from mist_config_guardian_backend.guardian.change import ObjectChange, build_change_set
from mist_config_guardian_backend.guardian.contracts import ExpectedDevice
from mist_config_guardian_backend.guardian.ledger import build_ledger
from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.plugins.dns import (
    CLIENT,
    CLIENT_METRICS,
    DUAL,
    INFRASTRUCTURE_FINDINGS,
    INFRASTRUCTURE_INCIDENTS,
    INFRASTRUCTURE_METRICS,
    MANAGEMENT,
    MAPPINGS,
    DnsPlugin,
    matches,
)

SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
OTHER_SITE = "11111111-2222-3333-4444-555555555555"
SWITCHES = ("020000000001", "020000000002", "020000000003")
APS = ("020000000011", "020000000012")
GATEWAY = "020000000021"


def devices(*, site: str = SITE) -> list[ExpectedDevice]:
    """The DNT-NTR cohort: three switches, two access points and a gateway, each typed by its own trigger."""
    return [
        *(ExpectedDevice(mac=mac, site_id=site, device_type="switch") for mac in SWITCHES),
        *(ExpectedDevice(mac=mac, site_id=site, device_type="ap") for mac in APS),
        ExpectedDevice(mac=GATEWAY, site_id=site, device_type="gateway"),
    ]


def change(  # noqa: PLR0913 - one changed object per argument, all defaulted
    *,
    object_type: str = "networktemplates",
    scope: str = "org",
    before: dict | None = None,
    after: dict | None = None,
    site_id: str | None = None,
    device_mac: str | None = None,
):
    return build_change_set(
        [
            ObjectChange(
                logical_object_id="object-1",
                scope=scope,  # type: ignore[arg-type]
                object_type=object_type,
                name="Corp template",
                version=2,
                before=before if before is not None else {"dns_servers": ["10.0.0.1"]},
                after=after if after is not None else {"dns_servers": ["10.0.0.9"]},
                site_id=site_id,
                device_mac=device_mac,
                mist_id="00000000-0000-0000-0000-00000000aaaa",
            )
        ]
    )


def planned(changes, cohort=None):
    plan = DnsPlugin().plan(changes, devices() if cohort is None else cohort)
    if plan is not None:
        base.validate_plan(DnsPlugin(), plan, changes)
    return plan


def observations(plan) -> set[tuple[str, str, str, tuple[tuple[str, ...], ...]]]:
    return {(o.target.device_mac or "", o.metric or "", o.empty_policy or "", o.paths) for o in plan.obligations}


# -- the frozen record ---------------------------------------------------------


def test_the_src_table_is_the_frozen_record_and_holds_nothing_it_does_not_verify():
    fixture = load_fixture(DNS_SEMANTICS_FIXTURE)["mappings"]
    recorded = {
        (row["object_type"], row["variant"], row["attribute"], row["semantics"]): (
            tuple(row["device_types"]),
            tuple(tuple(path) for path in row["paths"]),
        )
        for row in fixture
        if row["semantics"] != "unverified"
    }
    ported = {
        (item.object_type, item.variant, item.attribute, item.semantics): ((item.device_type,), item.paths)
        for item in MAPPINGS
    }
    assert ported == recorded
    # An attribute can hold both verified and unverified paths (``ip_config.dns`` against ``ip_config.use_mgmt_vrf``),
    # so the record keys semantics by path: no path this table claims may be one the record left unverified.
    unverified = {
        (row["object_type"], row["variant"], tuple(path))
        for row in fixture
        if row["semantics"] == "unverified"
        for path in row["paths"]
    }
    assert unverified
    assert not unverified & {(item.object_type, item.variant, path) for item in MAPPINGS for path in item.paths}


def test_every_verified_row_names_one_device_family_the_record_recorded():
    assert {item.device_type for item in MAPPINGS} == {"ap", "switch", "gateway", "mxedge"}
    assert {item.semantics for item in MAPPINGS} == {MANAGEMENT, CLIENT, DUAL}


# -- the dual-use rule (R12) ---------------------------------------------------


def test_a_dual_use_template_emits_both_obligation_sets_on_the_mapped_family_only():
    plan = planned(change())

    assert observations(plan) == {
        (mac, metric, policy, (("dns_servers", "0"),))
        for mac in SWITCHES
        for metric, policy in (
            (INFRASTRUCTURE_METRICS["switch"], "incomplete"),
            (CLIENT_METRICS["switch"], "not_exercised"),
        )
    }
    assert plan.incident_types == INFRASTRUCTURE_INCIDENTS
    assert plan.finding_kinds == INFRASTRUCTURE_FINDINGS


def test_the_dnt_ntr_change_claims_the_switch_rows_and_leaves_every_other_device_uncovered():
    changes = change()
    ledger = build_ledger(changes, devices(), {"dns": planned(changes)}, "audit")

    claimed = {row.target.device_mac for row in ledger.rows if row.resolution == "claimed"}
    uncovered = {row.target.device_mac for row in ledger.rows if row.resolution == "uncovered"}
    assert claimed == set(SWITCHES)
    assert uncovered == {*APS, GATEWAY}
    # Every targeted switch, and only a targeted switch, carries the core's deployment precondition.
    assert {o.target.device_mac for o in ledger.obligations if o.kind == "deployment"} == set(SWITCHES)
    assert all(row.resolution != "excluded" for row in ledger.rows)


def test_management_only_and_client_only_mappings_emit_one_set_each():
    management = planned(
        change(
            object_type="deviceprofiles",
            before={"ip_config": {"dns": ["10.0.0.1"]}},
            after={"ip_config": {"dns": ["10.0.0.2"]}},
        )
    )
    client = planned(
        change(
            object_type="wlans",
            scope="site",
            site_id=SITE,
            before={"no_static_dns": False},
            after={"no_static_dns": True},
        )
    )

    assert observations(management) == {
        (mac, INFRASTRUCTURE_METRICS["ap"], "incomplete", (("ip_config", "dns", "0"),)) for mac in APS
    }
    assert observations(client) == {(mac, CLIENT_METRICS["ap"], "not_exercised", (("no_static_dns",),)) for mac in APS}
    assert client.incident_types == ()
    assert client.finding_kinds == ()


@pytest.mark.parametrize(
    ("object_type", "scope", "before", "after"),
    [
        # Site-level dns_servers: the device types that consume it are not established.
        ("settings", "site", {"dns_servers": ["10.0.0.1"]}, {"dns_servers": ["10.0.0.2"]}),
        # mDNS forwarding is not resolver configuration.
        ("networktemplates", "org", {"mdns": {"enabled": False}}, {"mdns": {"enabled": True}}),
        # An attribute of an object type the record does not list at all.
        ("sitegroups", "org", {"dns_servers": ["10.0.0.1"]}, {"dns_servers": ["10.0.0.2"]}),
    ],
)
def test_an_unverified_attribute_stays_unhandled_and_its_rows_stay_uncovered(object_type, scope, before, after):
    changes = change(
        object_type=object_type, scope=scope, before=before, after=after, site_id=SITE if scope == "site" else None
    )
    assert planned(changes) is None

    ledger = build_ledger(changes, devices(), {}, "audit")
    assert {row.resolution for row in ledger.rows} == {"uncovered"}


def test_a_wildcard_mapping_claims_only_the_paths_it_matches():
    changes = change(
        object_type="switchprofiles",
        before={"dhcpd_config": {"vlan10": {"dns_servers": ["10.0.0.1"], "lease_time": 3600}}},
        after={"dhcpd_config": {"vlan10": {"dns_servers": ["10.0.0.2"], "lease_time": 7200}}},
    )
    plan = planned(changes)

    assert observations(plan) == {
        (mac, CLIENT_METRICS["switch"], "not_exercised", (("dhcpd_config", "vlan10", "dns_servers", "0"),))
        for mac in SWITCHES
    }
    # The lease time below the same attribute is not DNS, so the atom is not fully claimed on a targeted switch.
    ledger = build_ledger(changes, devices(), {"dns": plan}, "audit")
    assert {row.resolution for row in ledger.rows} == {"uncovered"}
    [switch_row] = [row for row in ledger.rows if row.target.device_mac == SWITCHES[0]]
    assert switch_row.uncovered_paths == (("dhcpd_config", "vlan10", "lease_time"),)
    assert switch_row.obligation_ids


def test_a_changed_device_is_targeted_only_when_the_mapping_matches_its_own_family():
    switch = change(
        object_type="devices",
        scope="site",
        site_id=SITE,
        device_mac=SWITCHES[0],
        before={"dns_servers": ["10.0.0.1"]},
        after={"dns_servers": ["10.0.0.2"]},
    )
    access_point = change(
        object_type="devices",
        scope="site",
        site_id=SITE,
        device_mac=APS[0],
        before={"dns_servers": ["10.0.0.1"]},
        after={"dns_servers": ["10.0.0.2"]},
    )

    assert {o.target.device_mac for o in planned(switch).obligations} == {SWITCHES[0]}
    # site:devices dns_servers is verified for switches and gateways only, so an access point is never claimed.
    assert planned(access_point) is None


def test_a_device_whose_family_no_trigger_established_is_never_targeted():
    untyped = [ExpectedDevice(mac=mac, site_id=SITE) for mac in SWITCHES]
    assert planned(change(), untyped) is None

    elsewhere = [ExpectedDevice(mac=mac, site_id=OTHER_SITE, device_type="switch") for mac in SWITCHES]
    site_scoped = change(object_type="settings", scope="site", site_id=SITE, before={}, after={})
    assert planned(site_scoped, elsewhere) is None


def test_a_site_setting_reaches_only_the_family_at_that_site():
    changes = change(
        object_type="settings",
        scope="site",
        site_id=SITE,
        before={"switch": {"dns_servers": ["10.0.0.1"]}},
        after={"switch": {"dns_servers": ["10.0.0.2"]}},
    )
    cohort = [*devices(), ExpectedDevice(mac="0200000000ff", site_id=OTHER_SITE, device_type="switch")]

    assert {o.target.device_mac for o in planned(changes, cohort).obligations} == set(SWITCHES)


async def test_the_dns_rule_reads_nothing_and_claims_no_rule_coverage():
    plugin = DnsPlugin()
    plan = planned(change())

    assert plugin.max_reads == 0
    assert await plugin.collect(plan, reader=None) == []  # type: ignore[arg-type]
    conclusion = plugin.evaluate(plan, [])
    assert conclusion.statuses == {}
    assert (conclusion.peak, conclusion.current) == ("none", "none")
    assert all(o.kind == "monitoring" for o in plan.obligations)


def test_a_verified_mapping_for_a_family_guardian_does_not_monitor_claims_nothing():
    changes = change(
        object_type="mxedges",
        before={"oob_ip_config": {"dns": ["10.0.0.1"]}},
        after={"oob_ip_config": {"dns": ["10.0.0.2"]}},
    )
    # The record classes the mxedge out-of-band resolver, but no mxedge carries a device trigger or an SLE metric.
    assert planned(changes) is None
    assert any(item.device_type == "mxedge" for item in MAPPINGS)


def test_a_verified_path_and_an_unverified_one_under_the_same_attribute_are_separated():
    changes = change(
        object_type="switchprofiles",
        before={"ip_config": {"dns": ["10.0.0.1"], "use_mgmt_vrf": False}},
        after={"ip_config": {"dns": ["10.0.0.2"], "use_mgmt_vrf": True}},
    )
    plan = planned(changes)
    ledger = build_ledger(changes, devices(), {"dns": plan}, "audit")

    assert {o.paths for o in plan.obligations} == {(("ip_config", "dns", "0"),)}
    [row] = [row for row in ledger.rows if row.target.device_mac == SWITCHES[0]]
    assert row.uncovered_paths == (("ip_config", "use_mgmt_vrf"),)


@pytest.mark.parametrize(
    ("pattern", "path", "result"),
    [
        (("dhcpd_config", "*", "dns_servers"), ("dhcpd_config", "vlan10", "dns_servers"), True),
        (("dhcpd_config", "*", "dns_servers"), ("dhcpd_config", "vlan10", "lease_time"), False),
        (("dns_servers",), ("dns_servers", "0"), True),
        (("dns_servers", "[]"), ("dns_servers", "0"), True),
        (("dns_servers", "[]"), ("dns_servers", "name"), False),
        (("dns_servers", "0"), ("dns_servers",), False),
    ],
)
def test_the_records_path_language_matches_a_changed_path_segment_by_segment(pattern, path, result):
    assert matches([pattern], path) is result
