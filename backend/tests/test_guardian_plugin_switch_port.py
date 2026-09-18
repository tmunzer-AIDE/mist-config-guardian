"""The switch-port plug-in: the ported port, PoE and managed-neighbour judgements, and neighbour privacy.

The positive cases are the ported ones: a previously active port that goes down, a previously *powered* port whose
PoE is disabled, and the recoveries, absences and contradictions that must never become health. The MAC an LLDP
neighbour claims is never read, stored or shown; only a managed access point of this organization is.
"""

from datetime import timedelta

import pytest

from mist_config_guardian_backend.guardian.change import ObjectChange, build_change_set
from mist_config_guardian_backend.guardian.contracts import ExpectedDevice
from mist_config_guardian_backend.guardian.evidence import (
    RULE_EVIDENCE_ITEM_BUDGET,
    EvidenceRegistry,
    json_size,
)
from mist_config_guardian_backend.guardian.ledger import build_ledger
from mist_config_guardian_backend.guardian.plugins import base
from mist_config_guardian_backend.guardian.plugins.switch_port import (
    AP_LIMIT,
    BOUNDED_LIST_REASON,
    CONTRADICTION_REASON,
    FOREIGN_EVENT_REASON,
    NEIGHBOUR_FIELDS,
    NO_BASELINE_LINK_REASON,
    NO_BASELINE_POWER_REASON,
    NO_LOSS_REASON,
    OUT_OF_WINDOW_REASON,
    SELECTOR_GAP,
    UNKNOWN_DEVICE_GAP,
    SwitchPortPlan,
    SwitchPortPlugin,
)
from mist_config_guardian_backend.guardian.reader import TransportError
from test_guardian_plugin_wlan import (
    AP,
    CHANGED_AT,
    ORG,
    SITE,
    SWITCH,
    WINDOWS,
    FakeRuleTransport,
    reader,
)

PORT = "ge-0/0/1"
OTHER_PORT = "ge-0/0/2"
NEIGHBOUR_MAC = "aabbccddeeff"
DEVICES = [
    ExpectedDevice(mac=SWITCH, site_id=SITE, device_type="switch"),
    ExpectedDevice(mac=AP, site_id=SITE, device_type="ap"),
]
EVENTS_PATH = f"/api/v1/sites/{SITE}/devices/events/search"
PORTS_PATH = f"/api/v1/sites/{SITE}/stats/ports/search"
DEVICES_PATH = f"/api/v1/orgs/{ORG}/stats/devices"


def port_change(before: dict | None = None, after: dict | None = None, *, device_mac: str = SWITCH):
    return build_change_set(
        [
            ObjectChange(
                logical_object_id="device-1",
                scope="site",
                object_type="devices",
                name="access-1",
                version=2,
                before=before if before is not None else {"port_config": {PORT: {"disabled": False}}},
                after=after if after is not None else {"port_config": {PORT: {"disabled": True}}},
                site_id=SITE,
                device_mac=device_mac,
                mist_id="00000000-0000-0000-0000-00000000dddd",
            )
        ]
    )


def event(kind: str, at, *, port: str = PORT, mac: str = SWITCH) -> dict:
    return {
        "type": kind,
        "timestamp": at.timestamp(),
        "mac": mac,
        "port_id": port,
        "site_id": SITE,
        "device_type": "switch",
    }


def events(*rows: dict) -> dict:
    return {"start": 0, "end": 0, "total": len(rows), "results": list(rows)}


def port_row(**overrides) -> dict:
    return {
        "site_id": SITE,
        "mac": SWITCH,
        "port_id": PORT,
        "type": "switch",
        "up": True,
        "poe_on": True,
        "power_draw": 12,
        "timestamp": (CHANGED_AT - timedelta(seconds=30)).timestamp(),
        "neighbor_mac": NEIGHBOUR_MAC,
    } | overrides


def access_point(*, port: str = PORT, status: str = "connected") -> list:
    return [
        {
            "mac": AP,
            "type": "ap",
            "org_id": ORG,
            "site_id": SITE,
            "status": status,
            "lldp_stats": {"eth0": {"chassis_id": SWITCH, "port_id": port}},
            "port_stat": {"eth0": {"up": True}},
        }
    ]


def transport_for(event_rows=(), *, snapshot=None, aps=None) -> FakeRuleTransport:
    """One transport that answers each of the plug-in's three reads."""
    answers = {
        EVENTS_PATH: events(*event_rows),
        PORTS_PATH: {"total": 1, "results": [snapshot if snapshot is not None else port_row()]},
        DEVICES_PATH: aps if aps is not None else access_point(),
    }
    return FakeRuleTransport(lambda path, _params: answers[path])


async def run(changes=None, transport=None, devices=None, registry=None):
    bounded = reader(transport if transport is not None else transport_for(), registry=registry or EvidenceRegistry())
    outcome = await base.run_rules(
        [SwitchPortPlugin()],
        changes if changes is not None else port_change(),
        DEVICES if devices is None else devices,
        bounded,
    )
    return outcome.plans.get("switch-port"), outcome.conclusions.get("switch-port"), bounded


def statuses(conclusion) -> set[tuple[str, str | None]]:
    return {(status.status, status.reason) for status in conclusion.statuses.values()}


# -- planning ------------------------------------------------------------------


def test_one_obligation_per_changed_port_attribute_on_the_exact_port():
    changes = port_change(
        {"port_config": {PORT: {"disabled": False, "poe_disabled": False}}},
        {"port_config": {PORT: {"disabled": True, "poe_disabled": True}}},
    )
    plan = SwitchPortPlugin().plan(changes, DEVICES)
    base.validate_plan(SwitchPortPlugin(), plan, changes)

    assert isinstance(plan, SwitchPortPlan)
    assert (plan.site_id, plan.device_mac, plan.port_id) == (SITE, SWITCH, PORT)
    assert {o.paths for o in plan.obligations} == {
        (("port_config", PORT, "disabled"),),
        (("port_config", PORT, "poe_disabled"),),
    }
    assert {o.target.port_id for o in plan.obligations} == {PORT}
    ledger = build_ledger(changes, DEVICES, {"switch-port": plan}, "audit")
    assert [row.resolution for row in ledger.rows if row.target.device_mac == SWITCH] == ["claimed"]


def test_an_edit_beside_the_handled_attributes_leaves_those_paths_uncovered():
    changes = port_change(
        {"port_config": {PORT: {"disabled": False, "description": "uplink"}}},
        {"port_config": {PORT: {"disabled": True, "description": "spare"}}},
    )
    plan = SwitchPortPlugin().plan(changes, DEVICES)
    ledger = build_ledger(changes, DEVICES, {"switch-port": plan}, "audit")

    [row] = [row for row in ledger.rows if row.target.device_mac == SWITCH]
    assert row.resolution == "uncovered"
    assert row.uncovered_paths == (("port_config", PORT, "description"),)
    assert row.obligation_ids


def test_a_selector_that_is_not_one_concrete_port_is_a_gap_and_claims_nothing():
    changes = port_change(
        {"port_config": {"ge-0/0/1-4": {"disabled": False}}},
        {"port_config": {"ge-0/0/1-4": {"disabled": True}}},
    )
    plan = SwitchPortPlugin().plan(changes, DEVICES)

    assert plan.obligations == ()
    assert plan.gaps == (SELECTOR_GAP,)


def test_a_device_whose_family_no_trigger_established_is_never_resolved():
    plan = SwitchPortPlugin().plan(port_change(), [ExpectedDevice(mac=SWITCH, site_id=SITE)])

    assert plan.obligations == ()
    assert plan.gaps == (UNKNOWN_DEVICE_GAP,)


def test_only_one_port_is_read_and_the_rest_stay_a_gap():
    changes = port_change(
        {"port_config": {PORT: {"disabled": False}, OTHER_PORT: {"disabled": False}}},
        {"port_config": {PORT: {"disabled": True}, OTHER_PORT: {"disabled": True}}},
    )
    plan = SwitchPortPlugin().plan(changes, DEVICES)

    assert plan.port_id == PORT
    assert any("further changed port" in gap for gap in plan.gaps)
    ledger = build_ledger(changes, DEVICES, {"switch-port": plan}, "audit")
    [row] = [row for row in ledger.rows if row.target.device_mac == SWITCH]
    assert row.uncovered_paths == (("port_config", OTHER_PORT, "disabled"),)


def test_a_port_container_on_an_object_that_is_not_a_device_is_not_this_rules_change():
    changes = build_change_set(
        [
            ObjectChange(
                logical_object_id="template-1",
                scope="org",
                object_type="networktemplates",
                name="corp",
                version=2,
                before={"port_config": {PORT: {"disabled": False}}},
                after={"port_config": {PORT: {"disabled": True}}},
                mist_id="00000000-0000-0000-0000-00000000cccc",
            )
        ]
    )
    assert SwitchPortPlugin().plan(changes, DEVICES) is None


# -- collection ----------------------------------------------------------------


async def test_the_reads_are_the_exact_port_history_its_current_state_and_the_managed_access_points():
    transport = transport_for(
        [event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT)]
    )
    _plan, _conclusion, bounded = await run(transport=transport)

    assert [path for path, _ in transport.reads] == [EVENTS_PATH, PORTS_PATH, DEVICES_PATH]
    history, snapshot, devices = (params for _path, params in transport.reads)
    assert (history["start"], history["end"]) == (
        str(int(WINDOWS.combined.start.timestamp())),
        str(int(WINDOWS.combined.end.timestamp())),
    )
    assert history["mac"] == SWITCH
    assert (snapshot["mac"], snapshot["port_id"], snapshot["device_type"]) == (SWITCH, PORT, "switch")
    assert "start" not in snapshot
    assert "start" not in devices
    assert devices["site_id"] == SITE
    assert bounded.budget.rule_reads == 3


async def test_the_access_points_are_read_only_when_there_is_a_loss_to_qualify():
    transport = transport_for([event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1))])
    _plan, _conclusion, bounded = await run(transport=transport)

    assert [path for path, _ in transport.reads] == [EVENTS_PATH, PORTS_PATH]
    assert bounded.budget.rule_reads == 2


# -- port availability ---------------------------------------------------------


async def test_port_recovery_preserves_peak_and_does_not_claim_an_access_point_failure():
    transport = transport_for(
        [
            event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)),
            event("SW_PORT_DOWN", CHANGED_AT + timedelta(seconds=1)),
            event("SW_PORT_UP", CHANGED_AT + timedelta(seconds=30)),
        ]
    )
    _plan, conclusion, _ = await run(transport=transport)

    assert (conclusion.peak, conclusion.current) == ("warning", "none")
    assert statuses(conclusion) == {("satisfied", None)}
    assert "alternate paths and causes remain unresolved" in conclusion.findings[0].text
    assert [device.mac for device in conclusion.impacted_devices] == [SWITCH]


@pytest.mark.parametrize(
    ("rows", "reason"),
    [
        ((), NO_LOSS_REASON),
        ((event("SW_PORT_DOWN", CHANGED_AT),), NO_BASELINE_LINK_REASON),
        ((event("SW_PORT_DOWN", CHANGED_AT - timedelta(minutes=5)),), NO_LOSS_REASON),
        (
            (
                event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)),
                event("SW_PORT_DOWN", CHANGED_AT, port=OTHER_PORT),
            ),
            NO_LOSS_REASON,
        ),
    ],
)
async def test_an_absent_or_unbaselined_loss_never_establishes_health(rows, reason):
    _plan, conclusion, _ = await run(transport=transport_for(rows))

    assert statuses(conclusion) == {("unsatisfied", reason)}
    assert (conclusion.peak, conclusion.current) == ("none", "none")


async def test_contradictory_same_time_events_cannot_be_ordered_into_a_verdict():
    transport = transport_for(
        [
            event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)),
            event("SW_PORT_DOWN", CHANGED_AT),
            event("SW_PORT_UP", CHANGED_AT),
        ]
    )
    _plan, conclusion, _ = await run(transport=transport)

    assert statuses(conclusion) == {("unsatisfied", CONTRADICTION_REASON)}


async def test_a_truncated_history_cannot_establish_state_or_recovery():
    transport = FakeRuleTransport(
        lambda path, _params: (
            {"results": [event("SW_PORT_DOWN", CHANGED_AT)], "total": 9}
            if path == EVENTS_PATH
            else {"total": 1, "results": [port_row()]}
        )
    )
    _plan, conclusion, _ = await run(transport=transport)

    assert statuses(conclusion) == {("unsatisfied", base.PARTIAL_REASON)}


# -- PoE -----------------------------------------------------------------------


def poe_change():
    return port_change(
        {"port_config": {PORT: {"poe_disabled": False}}},
        {"port_config": {PORT: {"poe_disabled": True}}},
    )


async def test_a_poe_enable_event_does_not_establish_prior_power_delivery():
    transport = transport_for(
        [
            event("SW_POE_PORT_ENABLED", CHANGED_AT - timedelta(minutes=1)),
            event("SW_POE_PORT_DISABLED", CHANGED_AT),
        ],
        snapshot=port_row(power_draw=0),
    )
    _plan, conclusion, _ = await run(poe_change(), transport)

    assert statuses(conclusion) == {("unsatisfied", NO_BASELINE_POWER_REASON)}


@pytest.mark.parametrize(
    ("power", "observed", "expected"),
    [
        (0, -30, "unsatisfied"),
        (12, 1, "unsatisfied"),
        (12, -360, "unsatisfied"),
        (12, None, "unsatisfied"),
        (12, -30, "satisfied"),
    ],
)
async def test_poe_loss_requires_recent_measured_power_before_the_change(power, observed, expected):
    snapshot = port_row(power_draw=power)
    snapshot["timestamp"] = None if observed is None else (CHANGED_AT + timedelta(seconds=observed)).timestamp()
    transport = transport_for([event("SW_POE_PORT_DISABLED", CHANGED_AT)], snapshot=snapshot)
    _plan, conclusion, _ = await run(poe_change(), transport)

    assert {status.status for status in conclusion.statuses.values()} == {expected}
    assert conclusion.peak == ("critical" if expected == "satisfied" else "none")
    # Enabling PoE again would not lower this, so current never recovers from an administrative enable.
    assert conclusion.current == conclusion.peak


async def test_restoring_power_administratively_is_not_restored_delivery():
    transport = transport_for(
        [event("SW_POE_PORT_DISABLED", CHANGED_AT), event("SW_POE_PORT_ENABLED", CHANGED_AT + timedelta(seconds=30))]
    )
    _plan, conclusion, _ = await run(poe_change(), transport)

    assert (conclusion.peak, conclusion.current) == ("critical", "critical")
    assert "AP failure is not established" in conclusion.findings[0].text


# -- neighbour privacy ---------------------------------------------------------


async def test_the_mac_an_lldp_neighbour_claims_never_reaches_stored_evidence():
    transport = transport_for(
        [event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT)],
        aps=[],
    )
    registry = EvidenceRegistry()
    _plan, conclusion, _ = await run(transport=transport, registry=registry)
    stored = [item.model_dump_json() for item in registry.evidence]

    # Mist returned the neighbour MAC; nothing a run would persist, and nothing the rule saw, kept it.
    assert any("neighbor_mac" in str(answer) for answer in [port_row()])
    assert stored
    assert all(NEIGHBOUR_MAC not in item for item in stored)
    assert all(field not in item for item in stored for field in NEIGHBOUR_FIELDS)
    assert all(NEIGHBOUR_MAC not in str(params) for _path, params in transport.reads)
    assert "No managed access point reports this port as its uplink" in conclusion.findings[0].text


async def test_a_managed_access_point_that_names_this_port_is_shown_with_the_loss():
    transport = transport_for(
        [event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT)]
    )
    _plan, conclusion, _ = await run(transport=transport)

    assert f"Managed access point {AP}" in conclusion.findings[0].text
    assert "sole power path and impact remain unproven" in conclusion.findings[0].text
    # The neighbour qualifies the loss; it is never reported as an impacted device of its own.
    assert [device.mac for device in conclusion.impacted_devices] == [SWITCH]


async def test_an_access_point_attached_to_another_port_is_not_this_ports_neighbour():
    transport = transport_for(
        [event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT)],
        aps=access_point(port=OTHER_PORT),
    )
    _plan, conclusion, _ = await run(transport=transport)

    assert "No managed access point reports this port as its uplink" in conclusion.findings[0].text


async def test_an_event_naming_another_device_or_carrying_no_time_cannot_be_ordered():
    for row in (event("SW_PORT_DOWN", CHANGED_AT, mac=AP), {**event("SW_PORT_DOWN", CHANGED_AT), "timestamp": None}):
        _plan, conclusion, _ = await run(transport=transport_for([row]))
        assert statuses(conclusion) == {("unsatisfied", FOREIGN_EVENT_REASON)}


async def test_an_event_outside_the_window_it_was_read_for_is_not_this_changes_history():
    outside = event("SW_PORT_DOWN", CHANGED_AT + timedelta(hours=2))
    _plan, conclusion, _ = await run(transport=transport_for([outside]))

    assert statuses(conclusion) == {("unsatisfied", OUT_OF_WINDOW_REASON)}


async def test_power_is_not_established_without_one_unique_port_row():
    transport = FakeRuleTransport(
        lambda path, _params: (
            events(event("SW_POE_PORT_DISABLED", CHANGED_AT))
            if path == EVENTS_PATH
            else {"total": 2, "results": [port_row(), port_row()]}
            if path == PORTS_PATH
            else access_point()
        )
    )
    _plan, conclusion, _ = await run(poe_change(), transport)

    assert statuses(conclusion) == {("unsatisfied", NO_BASELINE_POWER_REASON)}


async def test_an_access_point_snapshot_that_cannot_be_relied_on_says_so_beside_the_loss():
    transport = FakeRuleTransport(
        lambda path, _params: (
            events(event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT))
            if path == EVENTS_PATH
            else {"total": 1, "results": [port_row()]}
            if path == PORTS_PATH
            else TransportError("Mist returned HTTP 503")
        )
    )
    _plan, conclusion, _ = await run(transport=transport)

    # The loss still stands on its own evidence, and the failed neighbour read is named rather than assumed away.
    assert conclusion.peak == "warning"
    assert "read failed" in conclusion.findings[0].text
    assert conclusion.findings[0].evidence_ids == ("E1",)
    assert {status.status for status in conclusion.statuses.values()} == {"unsatisfied"}


async def test_the_port_rule_refuses_another_plug_ins_plan_and_reads_nothing_without_a_port():
    plan = SwitchPortPlugin().plan(port_change(), [ExpectedDevice(mac=SWITCH, site_id=SITE)])
    transport = FakeRuleTransport()
    bounded = reader(transport)

    assert await SwitchPortPlugin().collect(plan, bounded) == []
    assert transport.reads == []
    with pytest.raises(base.PluginError, match="another plug-in's plan"):
        SwitchPortPlugin().evaluate(base.PluginPlan(), [])


def many_access_points(count: int) -> list:
    """``count`` managed access points at this site, none of which names the changed port."""
    return [
        {
            "mac": f"0200000100{index:02x}",
            "type": "ap",
            "org_id": ORG,
            "site_id": SITE,
            "status": "connected",
            "lldp_stats": {"eth0": {"chassis_id": SWITCH, "port_id": OTHER_PORT}},
        }
        for index in range(count)
    ]


LOSS = (event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=1)), event("SW_PORT_DOWN", CHANGED_AT))


async def test_an_access_point_list_below_its_limit_can_carry_the_negative():
    _plan, conclusion, _ = await run(transport=transport_for(LOSS, aps=many_access_points(AP_LIMIT - 1)))

    assert "No managed access point reports this port as its uplink" in conclusion.findings[0].text
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}


async def test_an_access_point_list_at_its_limit_cannot_carry_the_negative():
    _plan, conclusion, _ = await run(transport=transport_for(LOSS, aps=many_access_points(AP_LIMIT)))

    assert "No managed access point reports this port as its uplink" not in conclusion.findings[0].text
    assert "came back at its row limit" in conclusion.findings[0].text
    # The loss it did observe still stands; what was attached to the port did not, so the observation is not covered.
    assert conclusion.peak == "warning"
    assert {(status.status, status.reason) for status in conclusion.statuses.values()} == {
        ("unsatisfied", BOUNDED_LIST_REASON)
    }


async def test_a_device_event_history_too_large_to_store_is_still_judged_in_full():
    noise = [
        event("SW_PORT_UP", CHANGED_AT - timedelta(minutes=2), port=f"ge-0/0/{index}")
        | {"text": f"port {index} came up after a long descriptive provider sentence"}
        for index in range(10, 90)
    ]
    registry = EvidenceRegistry()
    transport = transport_for((*LOSS, *noise))
    _plan, conclusion, _ = await run(transport=transport, registry=registry)

    stored = registry.evidence
    assert stored[0].representation == "digest"
    assert stored[0].payload["digest"]["rows"]["results"] == len(noise) + len(LOSS)
    assert all(json_size(item) <= RULE_EVIDENCE_ITEM_BUDGET for item in stored)
    assert conclusion.peak == "warning"
    assert "came up after a long descriptive" not in conclusion.model_dump_json()


@pytest.mark.parametrize("reported", ["02:00:00:00:00:01", "02-00-00-00-00-01", "020000000001".upper()])
async def test_a_port_event_names_this_switch_however_the_provider_formats_its_mac(reported):
    rows = [row | {"mac": reported} for row in LOSS]
    _plan, conclusion, _ = await run(transport=transport_for(rows))

    assert conclusion.peak == "warning"
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}


async def test_a_port_event_of_a_genuinely_different_switch_still_closes_the_history():
    rows = [row | {"mac": "0200000000ff"} for row in LOSS]
    _plan, conclusion, _ = await run(transport=transport_for(rows))

    assert statuses(conclusion) == {("unsatisfied", FOREIGN_EVENT_REASON)}
