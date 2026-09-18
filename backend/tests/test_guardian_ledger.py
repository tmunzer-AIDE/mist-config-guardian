"""Guardian's coverage ledger: row resolution, merged obligations, core preconditions, coverage and bounded views."""

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from guardian_verification import load_fixture
from mist_config_guardian_backend.guardian.change import (
    ChangedObject,
    ChangeSet,
    ObjectChange,
    build_change_set,
    change_view,
)
from mist_config_guardian_backend.guardian.contracts import (
    BANDS,
    MAX_MODEL_TURNS,
    MAX_TEXT_CHARS,
    ChangeAtom,
    CompactImpactedDevice,
    Contract,
    Evidence,
    EvidenceScope,
    EvidenceWindow,
    Exclusion,
    ExpectedDevice,
    Finding,
    Obligation,
    ObligationStatus,
    RulePlan,
    Target,
    band_rank,
)
from mist_config_guardian_backend.guardian.evidence import (
    CHANGE_VIEW_BUDGET,
    CONCLUSIONS_BUDGET,
    DEPLOYMENT_EVIDENCE_BUDGET,
    DETERMINISTIC_VIEW_BUDGET,
    FEEDBACK_BUDGET,
    IMPACTED_DEVICES_BUDGET,
    LEDGER_VIEW_BUDGET,
    MODEL_OUTPUT_BUDGET,
    MONITORING_EVIDENCE_BUDGET,
    PROMPT_FIXED_BUDGET,
    RUN_STORED_BUDGET,
    STEPS_BUDGET,
    SYSTEM_PROMPT_BUDGET,
    TOOL_CATALOGUE_BUDGET,
    WIDEST_EVIDENCE_ID,
    Bounded,
    EvidenceRegistry,
    bounded,
    json_size,
    pack,
)
from mist_config_guardian_backend.guardian.ledger import (
    ANCHOR_REASON,
    NO_STATUS_REASON,
    VIEW_REFERENCES,
    Ledger,
    LedgerError,
    RowDevices,
    build_ledger,
    coverage,
    deterministic_view,
    ledger_view,
    reaches,
    resolve_statuses,
)
from mist_config_guardian_backend.snapshots.diffing import MAX_ENTRIES

SITE_A = "site-a"
SITE_B = "site-b"
X = "0200000000a1"
Y = "0200000000a2"
Z = "0200000000b1"
OUTSIDER = "0200000000ff"
DEVICES = (
    ExpectedDevice(mac=X, site_id=SITE_A),
    ExpectedDevice(mac=Y, site_id=SITE_A),
    ExpectedDevice(mac=Z, site_id=SITE_B),
)
SITES = {device.mac: device.site_id for device in DEVICES}
P1 = ("port_config", "ge-0/0/1", "disabled")
P2 = ("port_config", "ge-0/0/2", "disabled")
DNS = (("dns_servers", "0"),)
NOW = datetime(2026, 9, 16, 5, 41, 35, tzinfo=UTC)

SATISFIED = ObligationStatus(status="satisfied")
NOT_EXERCISED = ObligationStatus(status="not_exercised")


def unsatisfied(reason: str = "No data in either window") -> ObligationStatus:
    return ObligationStatus(status="unsatisfied", reason=reason)


def status(value: str) -> ObligationStatus:
    return unsatisfied() if value == "unsatisfied" else ObligationStatus(status=value)


def change(*paths: tuple[tuple[str, ...], ...], incomplete: frozenset[str] = frozenset()) -> ChangeSet:
    """A1..An on one org template, each with the given paths."""
    template = ChangedObject(logical_object_id="template", scope="org", object_type="networktemplates", version=1)
    atoms = tuple(
        ChangeAtom(
            id=f"A{number}",
            logical_object_id="template",
            version=1,
            attribute=atom_paths[0][0],
            paths=atom_paths,
            paths_complete=f"A{number}" not in incomplete,
        )
        for number, atom_paths in enumerate(paths, start=1)
    )
    return ChangeSet(objects=(template,), atoms=atoms)


def device(mac: str, site: str | None = None, **refinement: str) -> Target:
    return Target(device_mac=mac, site_id=site, **refinement)


def site(site_id: str) -> Target:
    return Target(site_id=site_id)


def monitoring(  # noqa: PLR0913 - one argument per obligation field a case varies
    local: str,
    atom: str,
    paths: tuple[tuple[str, ...], ...],
    target: Target,
    *,
    metric: str = "dns-failure",
    policy: str = "not_exercised",
    owner: str = "dns",
) -> Obligation:
    return Obligation.model_validate(
        {
            "id": local,
            "owner": owner,
            "change_ref": atom,
            "paths": paths,
            "role": "observation",
            "kind": "monitoring",
            "target": target,
            "metric": metric,
            "empty_policy": policy,
        }
    )


def rule(
    local: str, atom: str, paths: tuple[tuple[str, ...], ...], target: Target, *, owner: str = "switch-port"
) -> Obligation:
    return Obligation(
        id=local, owner=owner, change_ref=atom, paths=paths, role="observation", kind="rule", target=target
    )


def exclusion(atom: str, paths: tuple[tuple[str, ...], ...], target: Target, *, owner: str = "dns") -> Exclusion:
    return Exclusion(owner=owner, change_ref=atom, paths=paths, target=target, reason="Not used by this device type")


def plans(*items: Obligation | Exclusion) -> dict[str, RulePlan]:
    owners = sorted({item.owner for item in items})
    return {
        owner: RulePlan(
            obligations=tuple(item for item in items if isinstance(item, Obligation) and item.owner == owner),
            exclusions=tuple(item for item in items if isinstance(item, Exclusion) and item.owner == owner),
        )
        for owner in owners
    }


def row_on(ledger: Ledger, atom: str, mac: str):
    [row] = [row for row in ledger.rows if row.atom_id == atom and row.target.device_mac == mac]
    return row


@pytest.mark.parametrize(
    ("paths", "complete", "items", "resolution", "claimed_by", "uncovered"),
    [
        pytest.param(
            (P1, P2),
            True,
            [rule("O1", "A1", (("port_config",),), device(X))],
            "claimed",
            [("switch-port", "O1")],
            (),
            id="one prefix covers every path",
        ),
        pytest.param(
            (P1, P2),
            True,
            [rule("O1", "A1", (P1[:2],), device(X)), rule("O2", "A1", (P2[:2],), device(X))],
            "claimed",
            [("switch-port", "O1"), ("switch-port", "O2")],
            (),
            id="union of obligation prefixes",
        ),
        pytest.param(
            (P1, P2),
            True,
            [rule("O1", "A1", (P1,), device(X)), exclusion("A1", (P2,), device(X))],
            "claimed",
            [("switch-port", "O1")],
            (),
            id="obligation and exclusion together",
        ),
        pytest.param(
            (P1, P2),
            True,
            [exclusion("A1", (("port_config",),), device(X))],
            "excluded",
            [],
            (),
            id="exclusions alone",
        ),
        pytest.param(
            (P1, P2),
            True,
            [rule("O1", "A1", (P1,), device(X))],
            "uncovered",
            [("switch-port", "O1")],
            (P2,),
            id="partial claim",
        ),
        pytest.param(
            (("ports", "10"),),
            True,
            [rule("O1", "A1", (("ports", "1"),), device(X))],
            "uncovered",
            [],
            (("ports", "10"),),
            id="prefixes compare whole segments",
        ),
        pytest.param((P1, P2), True, [], "uncovered", [], (P1, P2), id="nothing addresses the row"),
        pytest.param(
            (P1,),
            False,
            [rule("O1", "A1", (("port_config",),), device(X))],
            "uncovered",
            [("switch-port", "O1")],
            (("port_config",),),
            id="truncated paths stay uncovered",
        ),
        pytest.param(
            (P1,),
            True,
            [rule("O1", "A2", (("port_config",),), device(X))],
            "uncovered",
            [],
            (P1,),
            id="another atom's claim",
        ),
        pytest.param(
            (P1,),
            True,
            [exclusion("A1", (P1,), device(Y))],
            "uncovered",
            [],
            (P1,),
            id="another device's exclusion",
        ),
        pytest.param(
            (P1,),
            True,
            [rule("O1", "A1", (P1,), site(SITE_A))],
            "claimed",
            [("switch-port", "O1")],
            (),
            id="site-level claim contains the device",
        ),
        pytest.param(
            (P1,),
            True,
            [rule("O1", "A1", (P1,), site(SITE_B))],
            "uncovered",
            [],
            (P1,),
            id="another site's claim",
        ),
        pytest.param(
            (P1,),
            True,
            [rule("O1", "A1", (P1,), device(X, SITE_B))],
            "uncovered",
            [],
            (P1,),
            id="the device named at another site",
        ),
        pytest.param(
            (P1, P2),
            True,
            [
                rule("O1", "A1", (P1[:2],), device(X, SITE_A, port_id="ge-0/0/1")),
                rule("O2", "A1", (P2[:2],), device(X, SITE_A, port_id="ge-0/0/2")),
            ],
            "claimed",
            [("switch-port", "O1"), ("switch-port", "O2")],
            (),
            id="port-level obligations on the device",
        ),
        pytest.param(
            (P1,),
            True,
            [rule("O1", "A1", (("vlan",),), device(X)), exclusion("A1", (P1,), device(X))],
            "excluded",
            [],
            (),
            id="an obligation naming none of the atom's paths does not claim",
        ),
        pytest.param(
            (P1, P2),
            True,
            [monitoring("O1", "A1", (P1,), device(X)), rule("O1", "A1", (P2,), device(X))],
            "claimed",
            [("dns", "O1"), ("switch-port", "O1")],
            (),
            id="two plugins claim one row",
        ),
    ],
)
def test_each_row_resolves_one_way(paths, complete, items, resolution, claimed_by, uncovered):  # noqa: PLR0913, PLR0917
    ledger = build_ledger(
        change(paths, DNS, incomplete=frozenset() if complete else frozenset({"A1"})), DEVICES, plans(*items), "audit"
    )

    row = row_on(ledger, "A1", X)
    assert row.resolution == resolution
    assert row.obligation_ids == tuple(ledger.plan_ids[owner][local] for owner, local in claimed_by)
    assert row.uncovered_paths == uncovered


def test_rows_are_every_atom_on_every_applicable_target():
    template = ChangedObject(logical_object_id="template", scope="org", object_type="networktemplates", version=1)
    switch = ChangedObject(
        logical_object_id="switch", scope="site", object_type="devices", version=4, site_id=SITE_B, device_mac=OUTSIDER
    )
    change_set = ChangeSet(
        objects=(template, switch),
        atoms=(
            ChangeAtom(
                id="A1",
                logical_object_id="template",
                version=1,
                attribute="dns_servers",
                paths=DNS,
                paths_complete=True,
            ),
            ChangeAtom(
                id="A2",
                logical_object_id="switch",
                version=4,
                attribute="port_config",
                paths=(P1,),
                paths_complete=True,
            ),
        ),
    )
    ledger = build_ledger(change_set, (DEVICES[2], DEVICES[0], DEVICES[1]), {}, "audit")

    assert [(row.atom_id, row.target, row.resolution) for row in ledger.rows] == [
        ("A1", device(X, SITE_A), "uncovered"),
        ("A1", device(Y, SITE_A), "uncovered"),
        ("A1", device(Z, SITE_B), "uncovered"),
        ("A2", device(OUTSIDER, SITE_B), "uncovered"),
    ]


def test_every_uncovered_row_adds_an_unsatisfied_core_observation():
    many = tuple(("port_config", f"ge-0/0/{port}", "disabled") for port in range(40))
    ledger = build_ledger(
        change(many, DNS, incomplete=frozenset({"A2"})),
        DEVICES[:1],
        plans(rule("O1", "A1", (many[0],), device(X))),
        "audit",
    )

    uncovered = {o.change_ref: o for o in ledger.obligations if o.owner == "core" and o.role == "observation"}
    assert set(uncovered) == {"A1", "A2"}
    assert (uncovered["A1"].kind, uncovered["A1"].target, uncovered["A1"].paths) == (
        "rule",
        device(X, SITE_A),
        many[1:],
    )
    assert uncovered["A2"].paths == (("dns_servers",),)
    reasons = {atom: ledger.statuses[o.id] for atom, o in uncovered.items()}
    assert reasons["A1"].status == "unsatisfied"
    assert reasons["A1"].reason == (
        "no plugin addressed A1 port_config.ge-0/0/1.disabled, port_config.ge-0/0/2.disabled, "
        f"port_config.ge-0/0/3.disabled and 36 more on {X}"
    )
    assert reasons["A2"].reason == f"no plugin addressed A2 dns_servers (changed paths truncated) on {X}"


def test_an_uncovered_reason_stays_within_bounded_text():
    long_paths = tuple(("port_config", "p" * 128, str(index)) for index in range(3))
    ledger = build_ledger(change(long_paths), DEVICES[:1], {}, "audit")

    [reason] = [value.reason for value in ledger.statuses.values()]
    assert reason is not None
    assert len(reason) <= MAX_TEXT_CHARS


def test_an_exclusion_applies_to_its_atom_never_the_whole_device():
    ledger = build_ledger(
        change((P1,), DNS), DEVICES[:1], plans(exclusion("A1", (("port_config",),), device(X))), "audit"
    )

    assert row_on(ledger, "A1", X).resolution == "excluded"
    assert row_on(ledger, "A2", X).resolution == "uncovered"


@pytest.mark.parametrize(
    ("items", "merged"),
    [
        pytest.param(
            [
                monitoring("O1", "A1", DNS, device(X), policy="not_exercised"),
                monitoring("O2", "A1", DNS, device(X), policy="incomplete"),
            ],
            [("dns", "incomplete", {("dns", "O1"), ("dns", "O2")})],
            id="one plan, same device and metric",
        ),
        pytest.param(
            [
                monitoring("O1", "A1", DNS, device(X), policy="incomplete", owner="wlan-auth"),
                monitoring("O1", "A1", DNS, device(X), policy="not_exercised", owner="dns"),
            ],
            [("dns", "incomplete", {("dns", "O1"), ("wlan-auth", "O1")})],
            id="two plugins, same device and metric",
        ),
        pytest.param(
            [monitoring("O1", "A1", DNS, device(X)), monitoring("O2", "A1", DNS, device(X))],
            [("dns", "not_exercised", {("dns", "O1"), ("dns", "O2")})],
            id="both not exercised",
        ),
        pytest.param(
            [monitoring("O1", "A1", DNS, device(X)), monitoring("O2", "A2", (P1,), device(X), policy="incomplete")],
            [("dns", "incomplete", {("dns", "O1"), ("dns", "O2")})],
            id="across atoms",
        ),
        pytest.param(
            [monitoring("O1", "A1", DNS, device(X)), monitoring("O2", "A1", DNS, device(X), metric="app-health")],
            [("dns", "not_exercised", {("dns", "O1")}), ("dns", "not_exercised", {("dns", "O2")})],
            id="different metrics stay apart",
        ),
        pytest.param(
            [monitoring("O1", "A1", DNS, device(X)), monitoring("O2", "A1", DNS, device(Y), policy="incomplete")],
            [("dns", "not_exercised", {("dns", "O1")}), ("dns", "incomplete", {("dns", "O2")})],
            id="different devices stay apart",
        ),
    ],
)
def test_duplicate_monitoring_obligations_merge_to_the_strictest_empty_policy(items, merged):
    ledger = build_ledger(change(DNS, (P1,)), DEVICES, plans(*items), "audit")

    locals_by_id: dict[str, set[tuple[str, str]]] = {}
    for owner, ids in ledger.plan_ids.items():
        for local, global_id in ids.items():
            locals_by_id.setdefault(global_id, set()).add((owner, local))
    found = [(o.owner, o.empty_policy, locals_by_id[o.id]) for o in ledger.obligations if o.kind == "monitoring"]
    assert found == merged


def test_rows_of_both_atoms_name_the_merged_monitoring_obligation():
    ledger = build_ledger(
        change(DNS, (P1,)),
        DEVICES[:1],
        plans(monitoring("O1", "A1", DNS, device(X)), monitoring("O2", "A2", (P1,), device(X), policy="incomplete")),
        "audit",
    )

    merged = ledger.plan_ids["dns"]["O1"]
    assert ledger.plan_ids["dns"]["O2"] == merged
    assert row_on(ledger, "A1", X).obligation_ids == (merged,)
    assert row_on(ledger, "A2", X).obligation_ids == (merged,)


def test_a_rule_obligation_never_merges_into_a_monitoring_obligation():
    shared = device(X)
    observed = rule("O1", "A1", DNS, shared, owner="wlan-auth").model_copy(update={"metric": "dns-failure"})

    ledger = build_ledger(change(DNS), DEVICES[:1], plans(monitoring("O1", "A1", DNS, shared), observed), "audit")

    assert ledger.plan_ids["dns"]["O1"] != ledger.plan_ids["wlan-auth"]["O1"]
    assert [o.kind for o in ledger.obligations if o.owner != "core"] == ["monitoring", "rule"]


def test_a_target_naming_no_device_or_site_reaches_no_row():
    ledger = build_ledger(change(DNS), DEVICES, plans(rule("O1", "A1", DNS, Target(wlan_id="wlan-1"))), "audit")

    assert {row.resolution for row in ledger.rows} == {"uncovered"}
    assert not [o for o in ledger.obligations if o.kind == "deployment"]


def test_distinct_rule_obligations_are_all_kept():
    same = (P1,)
    ledger = build_ledger(
        change(same), DEVICES[:1], plans(rule("O1", "A1", same, device(X)), rule("O2", "A1", same, device(X))), "audit"
    )

    assert len({ledger.plan_ids["switch-port"]["O1"], ledger.plan_ids["switch-port"]["O2"]}) == 2
    assert row_on(ledger, "A1", X).obligation_ids == ("O1", "O2")


@pytest.mark.parametrize(
    ("items", "preconditioned"),
    [
        pytest.param([monitoring("O1", "A1", DNS, device(X))], [X], id="monitoring obligation"),
        pytest.param([rule("O1", "A1", DNS, device(Y))], [Y], id="rule obligation"),
        pytest.param([monitoring("O1", "A1", DNS, site(SITE_A))], [X, Y], id="site-level target contains devices"),
        pytest.param([exclusion("A1", DNS, device(X))], [], id="exclusion only"),
        pytest.param([exclusion("A1", DNS, site(SITE_A))], [], id="site-level exclusion only"),
        pytest.param([], [], id="nothing targets any device"),
        pytest.param(
            [monitoring("O1", "A1", DNS, device(X)), exclusion("A1", DNS, device(Z))], [X], id="claimed and excluded"
        ),
        pytest.param([rule("O1", "A1", (("vlan",),), device(Z))], [Z], id="targeted even when its paths claim nothing"),
        pytest.param([monitoring("O1", "A1", DNS, device(OUTSIDER))], [], id="a device the change does not reach"),
    ],
)
def test_deployment_preconditions_only_for_devices_an_obligation_targets(items, preconditioned):
    ledger = build_ledger(change(DNS), DEVICES, plans(*items), "audit")

    deployment = [o for o in ledger.obligations if o.kind == "deployment"]
    assert [o.target for o in deployment] == [device(mac, SITES[mac]) for mac in preconditioned]
    assert {(o.owner, o.role) for o in deployment} <= {("core", "precondition")}
    assert not {o.id for o in deployment} & set(ledger.statuses)


@pytest.mark.parametrize(
    ("target", "row", "expected"),
    [
        pytest.param(device(X), device(X, SITE_A), True, id="device"),
        pytest.param(device(X, SITE_A), device(X, SITE_A), True, id="device at its site"),
        pytest.param(device(X, SITE_B), device(X, SITE_A), False, id="device naming another site"),
        pytest.param(device(X, SITE_A), device(X), False, id="device naming a site its row lacks"),
        pytest.param(device(Y), device(X, SITE_A), False, id="another device"),
        pytest.param(site(SITE_A), device(X, SITE_A), True, id="site containing the device"),
        pytest.param(site(SITE_B), device(X, SITE_A), False, id="another site"),
        pytest.param(site(SITE_A), device(X), False, id="site of a row without a site"),
        pytest.param(Target(), device(X, SITE_A), False, id="neither"),
        pytest.param(device(X, SITE_A, port_id="ge-0/0/1"), device(X, SITE_A), True, id="port refinement"),
    ],
)
def test_the_one_targeting_rule(target, row, expected):
    assert reaches(target, row) is expected


@pytest.mark.parametrize(
    "items",
    [
        [monitoring("O1", "A1", DNS, device(X))],
        [rule("O1", "A1", DNS, device(Y, SITE_A)), monitoring("O2", "A1", DNS, device(Z, SITE_A))],
        [monitoring("O1", "A1", DNS, site(SITE_A)), rule("O2", "A1", DNS, device(OUTSIDER))],
        [monitoring("O1", "A1", DNS, site(SITE_B)), monitoring("O2", "A1", DNS, Target())],
        [exclusion("A1", DNS, device(X)), monitoring("O1", "A1", DNS, device(Z, SITE_B))],
    ],
)
def test_row_devices_reached_by_obligations_are_exactly_the_deployment_preconditioned_devices(items):
    ledger = build_ledger(change(DNS), DEVICES, plans(*items), "audit")
    devices = RowDevices.of(ledger)
    reached = {mac for o in ledger.obligations if o.owner != "core" for mac in devices.reached_by(o.target)}

    assert list(devices.targets) == sorted(SITES)
    assert reached == {o.target.device_mac for o in ledger.obligations if o.kind == "deployment"}
    assert OUTSIDER not in reached


def test_the_dnt_ntr_devices_excluded_from_a_client_mapping_get_no_deployment_precondition():
    fixture = load_fixture("dnt_ntr_change.json")
    devices = [ExpectedDevice(mac=item["device_mac"], site_id=fixture["site_id"]) for item in fixture["devices"]]
    switches = [item["device_mac"] for item in fixture["devices"] if item["device_type"] == "switch"]
    others = sorted(item["device_mac"] for item in fixture["devices"] if item["device_type"] != "switch")
    change_set = build_change_set(
        [
            ObjectChange(
                logical_object_id=fixture["changed_objects"][0]["logical_object_id"],
                scope="org",
                object_type="networktemplates",
                name="DNT-NTR",
                version=2,
                before={"dns_servers": ["10.0.0.1"], "modified_time": 1},
                after={"dns_servers": ["10.0.0.2"], "modified_time": 2},
            )
        ]
    )
    [atom] = change_set.atoms
    items = [
        *(exclusion(atom.id, (("dns_servers",),), device(mac)) for mac in switches),
        *(monitoring(f"O{n}", atom.id, (("dns_servers",),), device(mac)) for n, mac in enumerate(others, start=1)),
    ]

    ledger = build_ledger(change_set, devices, plans(*items), "audit")

    assert {row.target.device_mac: row.resolution for row in ledger.rows} == dict.fromkeys(
        switches, "excluded"
    ) | dict.fromkeys(others, "claimed")
    assert [o.target.device_mac for o in ledger.obligations if o.kind == "deployment"] == others


@pytest.mark.parametrize(("source", "anchored"), [("audit", False), ("device_trigger", False), ("receipt", True)])
def test_only_a_receipt_anchor_adds_the_always_unsatisfied_anchor_precondition(source, anchored):
    ledger = build_ledger(change(DNS), DEVICES, {}, source)

    anchors = [o for o in ledger.obligations if o.kind == "anchor"]
    assert len(anchors) == int(anchored)
    for anchor in anchors:
        assert (anchor.owner, anchor.role, anchor.target) == ("core", "precondition", Target())
        assert ledger.statuses[anchor.id] == unsatisfied(ANCHOR_REASON)


def test_a_receipt_anchor_prevents_complete_coverage():
    items = plans(*(monitoring(f"O{n}", "A1", DNS, device(d.mac)) for n, d in enumerate(DEVICES, start=1)))
    anchored = build_ledger(change(DNS), DEVICES, items, "receipt")
    known = build_ledger(change(DNS), DEVICES, items, "audit")
    everything_satisfied = {o.id: SATISFIED for o in anchored.obligations}

    assert coverage(known, everything_satisfied) == "complete"
    assert coverage(anchored, everything_satisfied) == "partial"


def test_an_input_the_attempt_never_saw_prevents_complete_coverage():
    items = plans(*(monitoring(f"O{n}", "A1", DNS, device(d.mac)) for n, d in enumerate(DEVICES, start=1)))
    whole = build_ledger(change(DNS), DEVICES, items, "audit")
    truncated = build_ledger(change(DNS), DEVICES, items, "audit", ("200 versions were not examined",))
    everything_satisfied = {o.id: SATISFIED for o in truncated.obligations}

    assert coverage(whole, everything_satisfied) == "complete"
    # The input observation is the core's own unsatisfied status, so nothing a source reports can raise it.
    assert coverage(truncated, everything_satisfied) == "partial"
    missing = [o for o in truncated.obligations if o.kind == "input"]
    assert len(missing) == 1
    assert (missing[0].owner, missing[0].role, missing[0].target) == ("core", "observation", Target())
    assert (missing[0].change_ref, missing[0].paths) == (None, ())
    assert truncated.statuses[missing[0].id] == unsatisfied("200 versions were not examined")


def test_an_atom_with_no_applicable_target_is_recorded_rather_than_left_to_silence():
    """An org atom whose applicable targets are the expected devices, of which this audit has none.

    Without its own observation the atom reaches no row, no obligation and no gap, and coverage would be whatever
    the remaining rows happened to leave — complete, when a device object in the same audit was fully claimed.
    """
    ledger = build_ledger(change(DNS), (), {}, "audit")

    assert ledger.rows == ()
    [untargeted] = [o for o in ledger.obligations if o.kind == "input"]
    assert (untargeted.owner, untargeted.role, untargeted.target) == ("core", "observation", Target())
    assert ledger.statuses[untargeted.id].status == "unsatisfied"
    assert "A1" in ledger.statuses[untargeted.id].reason
    # The caller composes exactly the gaps whose obligations already hold coverage down.
    assert ledger.gaps == (ledger.statuses[untargeted.id].reason,)
    assert coverage(ledger, {o.id: SATISFIED for o in ledger.obligations}) == "partial"


def test_an_untargeted_atom_holds_coverage_down_beside_a_device_atom_that_is_fully_claimed():
    """The case that matters: the audit also changed a device object, whose rows a plug-in claims in full."""
    device_object = ChangedObject(
        logical_object_id="switch", scope="site", object_type="devices", version=1, site_id="site-a", device_mac=X
    )
    org_atom = ChangeAtom(
        id="A1", logical_object_id="template", version=1, attribute="dns_servers", paths=DNS, paths_complete=True
    )
    device_atom = ChangeAtom(
        id="A2", logical_object_id="switch", version=1, attribute="port_config", paths=(P1,), paths_complete=True
    )
    both = ChangeSet(
        objects=(
            ChangedObject(logical_object_id="template", scope="org", object_type="networktemplates", version=1),
            device_object,
        ),
        atoms=(org_atom, device_atom),
    )
    items = plans(monitoring("O1", "A2", (P1,), device(X)))

    ledger = build_ledger(both, (), items, "audit")
    reported = {o.id: SATISFIED for o in ledger.obligations}

    assert [row.atom_id for row in ledger.rows] == ["A2"]
    assert [row.resolution for row in ledger.rows] == ["claimed"]
    assert coverage(ledger, reported) == "partial"


def test_an_input_observation_is_numbered_after_every_other_obligation():
    items = plans(monitoring("O1", "A1", DNS, device(X)))
    ledger = build_ledger(change(DNS), DEVICES, items, "receipt", ("one", "two"))

    inputs = [o.id for o in ledger.obligations if o.kind == "input"]
    assert inputs == [o.id for o in ledger.obligations][-2:]
    assert [ledger.statuses[o].reason for o in inputs] == ["one", "two"]


def test_an_input_obligation_names_itself_in_every_view():
    items = plans(monitoring("O1", "A1", DNS, device(X)))
    ledger = build_ledger(change(DNS), DEVICES, items, "receipt", ("the versions beyond the cap",))
    reported = {o.id: SATISFIED for o in ledger.obligations}

    view = deterministic_view(ledger, reported)
    kinds = [item.kind for item in view.unsatisfied.items]

    # It is derived from no change at all, so it never reads as an uncovered row, and it sorts with the anchor
    # ahead of the rows a plug-in could still have addressed.
    assert "input" in kinds
    assert kinds.index("input") < (kinds.index("rule") if "rule" in kinds else len(kinds))
    assert kinds[0] == "anchor"
    listed = [item for item in ledger_view(ledger, reported).obligations.items if item.kind == "input"]
    assert [item.change_ref for item in listed] == [None]
    assert [item.reason for item in listed] == ["the versions beyond the cap"]


def test_no_rule_plan_may_carry_a_core_input_obligation():
    missing = Obligation(id="O1", owner="core", role="observation", kind="input", target=Target())

    with pytest.raises(ValidationError, match="rule and monitoring observations only"):
        RulePlan(obligations=(missing,))


PRECONDITION = Obligation(id="O1", owner="core", role="precondition", kind="deployment", target=device(X, SITE_A))
OBSERVATIONS = (
    monitoring("O2", "A1", DNS, device(X, SITE_A)),
    rule("O3", "A1", DNS, device(X, SITE_A)),
)


@pytest.mark.parametrize(
    ("preconditions", "observations", "expected"),
    [
        pytest.param([], [], "insufficient", id="no obligations"),
        pytest.param(["satisfied"], [], "insufficient", id="preconditions without observations"),
        pytest.param(["unsatisfied"], [], "insufficient", id="no observations comes first"),
        pytest.param(["satisfied"], ["unsatisfied", "satisfied"], "partial", id="observation unsatisfied"),
        pytest.param(["unsatisfied"], ["satisfied", "satisfied"], "partial", id="precondition unsatisfied"),
        pytest.param(["unsatisfied"], ["not_exercised", "not_exercised"], "partial", id="unsatisfied over unexercised"),
        pytest.param(["satisfied"], ["not_exercised", "not_exercised"], "not_applicable", id="nothing exercised"),
        pytest.param(["satisfied"], ["satisfied", "not_exercised"], "complete", id="at least one satisfied"),
        pytest.param([], ["satisfied", "satisfied"], "complete", id="observations without preconditions"),
        pytest.param(["satisfied"], [None, "satisfied"], "partial", id="missing observation status"),
        pytest.param([None], ["satisfied", "satisfied"], "partial", id="missing precondition status"),
        pytest.param(["not_exercised"], ["satisfied", "satisfied"], "partial", id="a precondition must be satisfied"),
    ],
)
def test_the_deterministic_coverage_table(preconditions, observations, expected):
    obligations = (*[PRECONDITION][: len(preconditions)], *OBSERVATIONS[: len(observations)])
    values = [*preconditions, *observations]
    reported = {o.id: status(value) for o, value in zip(obligations, values, strict=True) if value is not None}

    assert coverage(Ledger(obligations=obligations), reported) == expected


def test_reported_statuses_never_override_the_core_statuses():
    anchor = Obligation(id="O1", owner="core", role="precondition", kind="anchor", target=Target())
    ledger = Ledger(obligations=(anchor, OBSERVATIONS[0]), statuses={"O1": unsatisfied(ANCHOR_REASON)})

    resolved = resolve_statuses(ledger, {"O1": SATISFIED, "O2": SATISFIED})

    assert resolved == {"O1": unsatisfied(ANCHOR_REASON), "O2": SATISFIED}
    assert coverage(ledger, {"O1": SATISFIED, "O2": SATISFIED}) == "partial"


def test_an_obligation_without_a_reported_status_resolves_unsatisfied():
    ledger = Ledger(obligations=OBSERVATIONS)

    assert resolve_statuses(ledger, {"O3": NOT_EXERCISED}) == {"O2": unsatisfied(NO_STATUS_REASON), "O3": NOT_EXERCISED}


def test_plugin_statuses_map_to_ledger_ids_for_the_plugins_own_rule_obligations_only():
    ledger = build_ledger(
        change(DNS),
        DEVICES,
        plans(
            monitoring("O1", "A1", DNS, device(X)),
            rule("O1", "A1", DNS, device(Y)),
            rule("O2", "A1", DNS, device(Z)),
        ),
        "audit",
    )

    assert ledger.rule_statuses("switch-port", {"O2": SATISFIED}) == {ledger.plan_ids["switch-port"]["O2"]: SATISFIED}
    with pytest.raises(LedgerError, match="O9"):
        ledger.rule_statuses("switch-port", {"O9": SATISFIED})
    with pytest.raises(LedgerError, match="O1"):
        ledger.rule_statuses("dns", {"O1": SATISFIED})
    with pytest.raises(LedgerError, match="wlan-auth"):
        ledger.rule_statuses("wlan-auth", {"O1": SATISFIED})


@pytest.mark.parametrize(
    ("items", "devices", "match"),
    [
        pytest.param(
            {"dns": RulePlan(obligations=(monitoring("O1", "A1", DNS, device(X), owner="wlan-auth"),))},
            DEVICES,
            "owned by",
            id="obligation owner",
        ),
        pytest.param(
            {"dns": RulePlan(exclusions=(exclusion("A1", DNS, device(X), owner="switch-port"),))},
            DEVICES,
            "owned by",
            id="exclusion owner",
        ),
        pytest.param(plans(monitoring("O1", "A9", DNS, device(X))), DEVICES, "A9", id="unknown atom"),
        pytest.param(plans(exclusion("A9", DNS, device(X))), DEVICES, "A9", id="unknown atom excluded"),
        pytest.param({"core": RulePlan()}, DEVICES, "core", id="core is not a plugin"),
        pytest.param({}, (*DEVICES, ExpectedDevice(mac=X, site_id=SITE_B)), "once", id="duplicate expected device"),
    ],
)
def test_invalid_ledger_inputs_are_refused(items, devices, match):
    with pytest.raises(LedgerError, match=match):
        build_ledger(change(DNS), devices, items, "audit")


def test_ledger_ids_do_not_depend_on_plan_or_device_order():
    items = [
        rule("O1", "A1", (P1,), site(SITE_A)),
        monitoring("O1", "A2", DNS, device(Z), owner="wlan-auth"),
        monitoring("O2", "A2", DNS, device(X)),
        exclusion("A1", (P2,), device(Y), owner="switch-port"),
    ]
    change_set = change((P1, P2), DNS)
    expected = build_ledger(change_set, DEVICES, plans(*items), "receipt")

    reordered = dict(reversed(list(plans(*items).items())))
    for devices in itertools.permutations(DEVICES):
        assert build_ledger(change_set, devices, reordered, "receipt") == expected
    assert [o.id for o in expected.obligations] == [f"O{n}" for n in range(1, len(expected.obligations) + 1)]
    assert [o.kind for o in expected.obligations[:1]] == ["anchor"]


def small_ledger() -> tuple[Ledger, dict[str, ObligationStatus]]:
    many = tuple(("port_config", f"ge-0/0/{port}", "disabled") for port in range(6))
    ledger = build_ledger(
        change(many, DNS, ((("vlan",),))),
        DEVICES,
        plans(
            *(rule(f"O{n}", "A1", (path,), device(X)) for n, path in enumerate(many[:5], start=1)),
            monitoring("O1", "A2", DNS, site(SITE_A)),
            exclusion("A2", DNS, device(Z)),
        ),
        "receipt",
    )
    reported = {o.id: SATISFIED for o in ledger.obligations if o.kind == "rule" and o.owner != "core"}
    reported |= {o.id: NOT_EXERCISED for o in ledger.obligations if o.kind == "monitoring"}
    return ledger, reported


def test_the_ledger_view_leads_with_uncovered_rows_and_unsatisfied_obligations():
    ledger, reported = small_ledger()

    view = ledger_view(ledger, reported)

    assert view.rows.omitted == {}
    assert view.obligations.omitted == {}
    assert [row.resolution for row in view.rows.items] == sorted(
        (row.resolution for row in ledger.rows), key=["uncovered", "claimed", "excluded"].index
    )
    statuses = [item.status for item in view.obligations.items]
    assert statuses == sorted(statuses, key=["unsatisfied", "not_exercised", "satisfied"].index)
    assert view.obligations.items[0].kind == "anchor"
    [partial] = [row for row in view.rows.items if row.atom_id == "A1" and row.device_mac == X]
    assert (len(partial.obligation_ids), partial.obligation_count) == (VIEW_REFERENCES, 5)
    assert (partial.uncovered_paths, partial.uncovered_count) == ((("port_config", "ge-0/0/5", "disabled"),), 1)


def test_the_deterministic_view_lists_only_unsatisfied_obligations_with_the_coverage():
    ledger, reported = small_ledger()

    view = deterministic_view(ledger, reported)

    assert view.coverage == coverage(ledger, reported) == "partial"
    resolved = resolve_statuses(ledger, reported)
    assert {item.id for item in view.unsatisfied.items} == {
        obligation_id for obligation_id, value in resolved.items() if value.status == "unsatisfied"
    }
    assert all(item.reason for item in view.unsatisfied.items)


@pytest.mark.parametrize("budget", [900, 2_000, 6_000, 24_000])
def test_compacting_a_view_changes_what_is_shown_never_coverage(budget):
    ledger, reported = small_ledger()
    before = coverage(ledger, reported)

    ledger_part = ledger_view(ledger, reported, budget=budget)
    deterministic = deterministic_view(ledger, reported, budget=budget)

    assert json_size(ledger_part) <= budget
    assert json_size(deterministic) <= budget
    assert len(ledger_part.rows.items) + ledger_part.rows.omitted_count == len(ledger.rows)
    assert len(ledger_part.obligations.items) + ledger_part.obligations.omitted_count == len(ledger.obligations)
    assert deterministic.coverage == coverage(ledger, reported) == before


# The worst case: 1,000 expected devices, a template edit with every kind of row, and every stored view at its limit.


class Step(Contract):
    turn: int
    action: str
    output: str
    rejection: str | None = None
    call: dict[str, str] | None = None
    prompt_hash: str
    visible_evidence_ids: tuple[str, ...] = ()
    withheld_evidence_ids: tuple[str, ...] = ()


class ConclusionsView(Contract):
    findings: Bounded[Finding]


def worst_case_devices() -> list[ExpectedDevice]:
    return [ExpectedDevice(mac=f"02{index:010x}", site_id=f"site-{index % 10}") for index in range(1_000)]


def worst_case_change() -> ChangeSet:
    long_value = "v" * 300
    before = {
        "dns_servers": ["10.0.0.1", "10.0.0.2"],
        "port_config": {
            f"ge-{fpc}/0/{port}": {"disabled": False, "usage": long_value} for fpc in range(4) for port in range(48)
        },
        "switch_mgmt": {"root_password": {"$encrypted": "one", "$fingerprint": "f1"}},
        "ntp_servers": ["10.0.1.1"],
        "modified_time": 1,
    }
    after = {
        "dns_servers": ["10.0.0.3", "10.0.0.4"],
        "port_config": {
            f"ge-{fpc}/0/{port}": {"disabled": True, "usage": f"{long_value}!"}
            for fpc in range(4)
            for port in range(48)
        },
        "switch_mgmt": {"root_password": {"$encrypted": "two", "$fingerprint": "f2"}},
        "ntp_servers": ["10.0.1.2"],
        "modified_time": 2,
    }
    truncated_before = {
        f"attribute_{group}": dict.fromkeys(map(str, range(MAX_ENTRIES // 2 + 10)), 0) for group in "ab"
    }
    truncated_after = {name: dict.fromkeys(values, 1) for name, values in truncated_before.items()}
    switch_before = {f"attribute_{index:02}": [long_value] * 5 for index in range(60)}
    switch_after = {name: [f"{long_value}!"] * 5 for name in switch_before}
    return build_change_set(
        [
            ObjectChange("template", "org", "networktemplates", "N" * 300, 9, before, after),
            ObjectChange("settings", "org", "settings", "Org settings", 3, truncated_before, truncated_after),
            ObjectChange("switch", "site", "devices", "SW", 2, switch_before, switch_after, "site-0", "02" + "0" * 10),
        ]
    )


def worst_case_ledger(devices: list[ExpectedDevice], change_set: ChangeSet) -> Ledger:
    atoms = {atom.attribute: atom for atom in change_set.atoms if atom.logical_object_id == "template"}
    dns, ports = atoms["dns_servers"], atoms["port_config"]
    items: list[Obligation | Exclusion] = []
    local = 0
    for number, expected in enumerate(devices):
        target = device(expected.mac, expected.site_id)
        if number % 10 == 0:
            items.append(exclusion(dns.id, (("dns_servers",),), target))
            continue
        for metric, policy in (
            ("dns-failure", "not_exercised"),
            ("dns-failure", "incomplete"),
            ("infra", "incomplete"),
        ):
            local += 1
            items.append(monitoring(f"O{local}", dns.id, (("dns_servers",),), target, metric=metric, policy=policy))
    items.extend(rule(f"O{n + 1}", ports.id, (("port_config", "ge-0/0/1"),), site(f"site-{n}")) for n in range(10))
    return build_ledger(change_set, devices, plans(*items), "receipt")


def worst_case_statuses(ledger: Ledger) -> dict[str, ObligationStatus]:
    reason = "r" * MAX_TEXT_CHARS
    evidence_ids = tuple(f"E{number}" for number in range(100_000, 100_020))
    return {
        o.id: ObligationStatus(status="unsatisfied", reason=reason, evidence_ids=evidence_ids)
        for o in ledger.obligations
        if o.owner != "core"
    } | {
        o.id: ObligationStatus(status="unsatisfied", reason=reason)
        for o in ledger.obligations
        if o.kind == "deployment"
    }


def monitoring_item(expected: ExpectedDevice, number: int) -> Evidence:
    treatment = ("unsatisfied", "not_exercised", "satisfied")[number % 3]
    return Evidence(
        id=WIDEST_EVIDENCE_ID,
        source="monitoring",
        kind="service_health",
        title=f"Monitoring {expected.mac}",
        captured_at=NOW,
        window=EvidenceWindow(start=NOW - timedelta(hours=1), end=NOW),
        scope=EvidenceScope(site_ids=(expected.site_id,), device_macs=(expected.mac,)),
        collection="complete",
        representation="full",
        payload={
            "device": expected.mac,
            "severity": BANDS[number % 4],
            "treatment": treatment,
            "exclusive": True,
            "deployment": "unsatisfied",
            "checks": [
                {
                    "metric": metric,
                    "before": "measured",
                    "after": "no_data",
                    "value_before": 0.98,
                    "value_after": None,
                    "treatment": treatment,
                }
                for metric in ("dns-failure", "infra", "client-connect")
            ],
        },
    )


def monitoring_digest(counts: dict[str, int]) -> Evidence:
    return Evidence(
        id=WIDEST_EVIDENCE_ID,
        source="monitoring",
        kind="service_health",
        title="Monitoring digest",
        captured_at=NOW,
        collection="complete",
        representation="digest",
        payload={"devices_by_treatment": dict(counts)},
        detail="Devices beyond the monitoring budget, counted by treatment",
    )


def test_a_worst_case_1000_device_attempt_fits_every_view_budget_and_compaction_never_changes_coverage():  # noqa: PLR0915
    devices = worst_case_devices()
    change_set = worst_case_change()
    ledger = worst_case_ledger(devices, change_set)
    statuses = worst_case_statuses(ledger)
    covered = coverage(ledger, statuses)
    snapshot = ledger.model_copy(deep=True)
    device_atoms = [atom for atom in change_set.atoms if change_set.object_of(atom).device_mac is not None]
    assert len(ledger.rows) == (len(change_set.atoms) - len(device_atoms)) * len(devices) + len(device_atoms)
    assert {row.resolution for row in ledger.rows} == {"claimed", "excluded", "uncovered"}
    assert not all(atom.paths_complete for atom in change_set.atoms)

    # Change and deterministic views.
    change = change_view(change_set)
    deterministic = deterministic_view(ledger, statuses)
    assert json_size(change) <= CHANGE_VIEW_BUDGET
    assert len(change.items) + change.omitted_count == len(change_set.atoms)
    assert change.omitted_count > 0
    assert json_size(deterministic) <= DETERMINISTIC_VIEW_BUDGET
    unsatisfied_count = sum(value.status == "unsatisfied" for value in resolve_statuses(ledger, statuses).values())
    assert len(deterministic.unsatisfied.items) + deterministic.unsatisfied.omitted_count == unsatisfied_count

    # Ledger rows and obligation statuses.
    stored_ledger = ledger_view(ledger, statuses)
    assert json_size(stored_ledger) <= LEDGER_VIEW_BUDGET
    assert len(stored_ledger.rows.items) + stored_ledger.rows.omitted_count == len(ledger.rows)
    assert len(stored_ledger.obligations.items) + stored_ledger.obligations.omitted_count == len(ledger.obligations)

    # Monitoring: full items in priority order, then one digest item counting every other device by treatment.
    registry = EvidenceRegistry()
    candidates = [monitoring_item(expected, number) for number, expected in enumerate(devices)]
    packed = pack(
        candidates,
        budget=MONITORING_EVIDENCE_BUDGET,
        priority=lambda item: (
            band_rank("warning") > band_rank(item.payload["severity"]),
            item.payload["treatment"] != "unsatisfied",
            item.scope.device_macs,
        ),
        category=lambda item: str(item.payload["treatment"]),
        overhead=lambda omitted, _kept: json_size(monitoring_digest(dict(omitted))),
    )
    for item in packed.kept:
        registry.record(item.model_copy(update={"id": registry.reserve("monitoring")}))
    registry.record(monitoring_digest(packed.omitted).model_copy(update={"id": registry.reserve("monitoring")}))
    monitoring_bytes = sum(json_size(item) for item in registry.evidence)
    assert monitoring_bytes <= MONITORING_EVIDENCE_BUDGET
    assert len(packed.kept) + sum(packed.omitted.values()) == len(devices)
    assert all(item.payload["severity"] in {"warning", "critical"} for item in packed.kept)

    # Deployment: one item, full rows for unsatisfied devices first, the rest counted.
    deployment_rows = [
        {
            "mac": d.mac,
            "trigger": "SW_CONFIG_CHANGED_BY_USER",
            "outcomes": [],
            "correlation": "none",
            "peak": "none",
            "current": "unknown",
            "precondition": "unsatisfied" if n % 2 else "satisfied",
        }
        for n, d in enumerate(devices)
    ]
    deployment = bounded(
        deployment_rows,
        budget=DEPLOYMENT_EVIDENCE_BUDGET,
        priority=lambda row: (row["precondition"] != "unsatisfied", row["mac"]),
        category=lambda row: str(row["precondition"]),
        build=lambda kept, omitted: Evidence(
            id=WIDEST_EVIDENCE_ID,
            source="deployment",
            kind="deployment",
            title="Deployment pairing",
            captured_at=NOW,
            collection="complete",
            representation="digest" if omitted else "full",
            payload={"rows": list(kept), "omitted": omitted},
        ),
    )
    registry.record(deployment.model_copy(update={"id": registry.reserve("deployment")}))
    assert json_size(deployment) <= DEPLOYMENT_EVIDENCE_BUDGET

    # Conclusions, impacted devices and steps, through the same digest mechanism.
    findings = [
        Finding(
            text=f"{d.mac} lost DNS resolution after the change " + "x" * 400,
            severity="warning",
            evidence_ids=("E1", "E2"),
        )
        for d in devices
    ]
    conclusions = bounded(
        findings,
        budget=CONCLUSIONS_BUDGET,
        priority=lambda finding: (-band_rank(finding.severity), finding.text),
        category=lambda finding: finding.severity,
        build=lambda kept, omitted: ConclusionsView(findings=Bounded[Finding](items=kept, omitted=omitted)),
    )
    impacted = bounded(
        [
            CompactImpactedDevice(mac=d.mac, site_id=d.site_id, name="D" * 128, peak=BANDS[n % 4], current="none")
            for n, d in enumerate(devices)
        ],
        budget=IMPACTED_DEVICES_BUDGET,
        priority=lambda row: (-band_rank(row.peak), -band_rank(row.current), row.mac),
        category=lambda row: row.peak,
        build=lambda kept, omitted: Bounded[CompactImpactedDevice](items=kept, omitted=omitted),
    )
    steps = bounded(
        [
            Step(
                turn=turn,
                action="call" if turn < 8 else "report",
                output="o" * MODEL_OUTPUT_BUDGET,
                rejection="Action rejected (citation_invalid): " + "d" * 200 if turn % 3 == 0 else None,
                call={
                    "tool": "search_events",
                    "evidence_id": f"E{turn}",
                    "arguments": "a" * 200,
                    "collection": "complete",
                },
                prompt_hash="h" * 64,
                visible_evidence_ids=tuple(f"E{n}" for n in range(1, 16)),
                withheld_evidence_ids=tuple(f"E{n}" for n in range(16, 23)),
            )
            for turn in range(1, MAX_MODEL_TURNS + 1)
        ],
        budget=STEPS_BUDGET,
        priority=lambda step: step.turn,
        category=lambda step: step.action,
        build=lambda kept, omitted: Bounded[Step](items=kept, omitted=omitted),
    )
    assert json_size(conclusions) <= CONCLUSIONS_BUDGET
    assert conclusions.findings.omitted_count > 0
    assert json_size(impacted) <= IMPACTED_DEVICES_BUDGET
    assert len(impacted.items) + impacted.omitted_count == len(devices)
    assert [row.peak for row in impacted.items[:1]] == ["critical"]
    assert json_size(steps) <= STEPS_BUDGET
    assert steps.omitted == {}

    # The fixed prompt part and the stored views stay within their sums.
    fixed = SYSTEM_PROMPT_BUDGET + TOOL_CATALOGUE_BUDGET + FEEDBACK_BUDGET
    fixed += json_size(change) + json_size(deterministic) + monitoring_bytes + json_size(deployment)
    assert fixed <= PROMPT_FIXED_BUDGET
    stored = sum(json_size(view) for view in (change, deterministic, stored_ledger, conclusions, impacted, steps))
    assert stored + monitoring_bytes + json_size(deployment) <= RUN_STORED_BUDGET

    # Compaction never changed coverage, and a digest-only view still leaves it unchanged.
    assert ledger == snapshot
    assert coverage(ledger, statuses) == covered == "partial"
    digest_only = deterministic_view(ledger, statuses, budget=400)
    assert digest_only.unsatisfied.items == ()
    assert digest_only.unsatisfied.omitted_count == unsatisfied_count
    assert digest_only.coverage == covered
