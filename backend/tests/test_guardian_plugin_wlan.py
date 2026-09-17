"""The WLAN plug-ins, and the boundary every plug-in runs behind.

The disruption cases are the ported ones: a previously connected client that disconnects, a client that
authenticated before the change and failed after it, and the recoveries and unknowns that must not become health.
Every read goes through the Reader with injected transports; nothing here reaches a network.
"""

# The fake transport mirrors the Reader's protocol, whose ``timeout`` is an HTTP bound, not an asyncio one.
# ruff: noqa: ASYNC109

from datetime import UTC, datetime, timedelta

import pytest

from mist_config_guardian_backend.guardian.change import ObjectChange, build_change_set
from mist_config_guardian_backend.guardian.contracts import (
    MAX_RULE_READS,
    Conclusion,
    ExpectedDevice,
    ObligationStatus,
    RulePlan,
)
from mist_config_guardian_backend.guardian.evidence import EvidenceRegistry
from mist_config_guardian_backend.guardian.ledger import build_ledger
from mist_config_guardian_backend.guardian.plugins import PLUGINS, base
from mist_config_guardian_backend.guardian.plugins.wlan_auth import WlanAuthPlan, WlanAuthPlugin
from mist_config_guardian_backend.guardian.plugins.wlan_removal import WlanRemovalPlan, WlanRemovalPlugin
from mist_config_guardian_backend.guardian.reader import (
    Reader,
    ReadRejectedError,
    SiteAuthority,
    TransportError,
    evidence_windows,
)

ORG = "4ac1dcf4-9d8b-7211-65c4-057819f0862b"
SITE = "978c48e6-6ef6-11e6-8bbf-02e208b2d34f"
WLAN = "00000000-0000-0000-0000-0000000000a1"
OTHER_WLAN = "00000000-0000-0000-0000-0000000000b2"
AP = "020000000011"
OTHER_AP = "020000000012"
SWITCH = "020000000001"
CLIENT = "001122334455"
OTHER_CLIENT = "001122334466"
CHANGED_AT = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)
AS_OF = CHANGED_AT + timedelta(minutes=60)
WINDOWS = evidence_windows(CHANGED_AT, AS_OF)
BEFORE_START = str(int(WINDOWS.before.start.timestamp()))

REFUSED = "the rule phase deadline"
DEVICES = [
    ExpectedDevice(mac=AP, site_id=SITE, device_type="ap"),
    ExpectedDevice(mac=OTHER_AP, site_id=SITE, device_type="ap"),
    ExpectedDevice(mac=SWITCH, site_id=SITE, device_type="switch"),
]


class FakeRuleTransport:
    """The Mist transport the Reader is given; it records what each plug-in asked for."""

    def __init__(self, results=None) -> None:
        self._results = results if results is not None else {"results": [], "total": 0}
        self.reads: list[tuple[str, dict]] = []

    async def fetch(self, path: str, params: dict, *, timeout: float, max_bytes: int):  # noqa: ARG002 - the Reader's bounds are its own tests' subject
        self.reads.append((path, dict(params)))
        result = self._results(path, params) if callable(self._results) else self._results
        if isinstance(result, Exception):
            raise result
        return result


def reader(transport: FakeRuleTransport | None = None, **overrides) -> Reader:
    values = {
        "org_id": ORG,
        "authority": SiteAuthority(site_ids=frozenset({SITE})),
        "windows": WINDOWS,
        "registry": EvidenceRegistry(),
        "deadlines": {"rule": 90.0, "agent": 210.0},
        "rule_allowances": base.rule_allowances(PLUGINS),
        "clock": lambda: 0.0,
        "rule_transport": transport if transport is not None else FakeRuleTransport(),
    }
    return Reader(**(values | overrides))


def wlan_change(  # noqa: PLR0913 - one changed WLAN per argument, all defaulted
    *,
    before: dict | None = None,
    after: dict | None = None,
    scope: str = "site",
    site_id: str | None = SITE,
    mist_id: str | None = WLAN,
    name: str = "corp",
):
    return build_change_set(
        [
            ObjectChange(
                logical_object_id="wlan-1",
                scope=scope,  # type: ignore[arg-type]
                object_type="wlans",
                name=name,
                version=2,
                before=before if before is not None else {"enabled": True, "ssid": "corp"},
                after=after if after is not None else {},
                site_id=site_id,
                mist_id=mist_id,
            )
        ]
    )


def session(*, client: str = CLIENT, connect: float, disconnect: float | None, access_point: str = AP) -> dict:
    return {
        "mac": client,
        "ap": access_point,
        "wlan_id": WLAN,
        "site_id": SITE,
        "connect": connect,
        "disconnect": disconnect,
    }


def sessions(*rows: dict) -> dict:
    return {"start": 0, "end": 0, "total": len(rows), "results": list(rows)}


def auth_event(*, kind: str, at: datetime, client: str = CLIENT, wlan: str = WLAN) -> dict:
    return {"type": kind, "timestamp": at.timestamp(), "mac": client, "ap": AP, "wlan_id": wlan, "site_id": SITE}


async def run(plugin, changes, *, transport=None, devices=None, charged: Reader | None = None):
    """Plan, collect and evaluate one plug-in exactly as the boundary does, and hand back what it produced."""
    bounded = charged if charged is not None else reader(transport)
    outcome = await base.run_rules([plugin], changes, DEVICES if devices is None else devices, bounded)
    return outcome.plans.get(plugin.id), outcome.conclusions.get(plugin.id), bounded


# -- wlan-removal: planning ----------------------------------------------------


def test_a_deleted_site_wlan_claims_every_atom_on_every_access_point():
    changes = wlan_change()
    plan = WlanRemovalPlugin().plan(changes, DEVICES)
    base.validate_plan(WlanRemovalPlugin(), plan, changes)

    assert isinstance(plan, WlanRemovalPlan)
    assert (plan.site_id, plan.wlan_id, plan.label) == (SITE, WLAN, "corp")
    assert {(o.change_ref, o.target.device_mac, o.target.wlan_id) for o in plan.obligations} == {
        (atom.id, mac, WLAN) for atom in changes.atoms for mac in (AP, OTHER_AP)
    }
    assert all(o.kind == "rule" and o.role == "observation" for o in plan.obligations)
    # Every access point's row is claimed; the switch is not an applicable target of a WLAN and stays uncovered.
    ledger = build_ledger(changes, DEVICES, {"wlan-removal": plan}, "audit")
    assert {row.target.device_mac for row in ledger.rows if row.resolution == "claimed"} == {AP, OTHER_AP}
    assert {row.target.device_mac for row in ledger.rows if row.resolution == "uncovered"} == {SWITCH}


def test_a_disabled_wlan_does_not_swallow_the_other_attributes_it_was_changed_with():
    changes = wlan_change(
        before={"enabled": True, "vlan_id": 10},
        after={"enabled": False, "vlan_id": 20},
    )
    plan = WlanRemovalPlugin().plan(changes, DEVICES)
    base.validate_plan(WlanRemovalPlugin(), plan, changes)

    [enabled] = [atom for atom in changes.atoms if atom.attribute == "enabled"]
    assert {o.change_ref for o in plan.obligations} == {enabled.id}
    ledger = build_ledger(changes, DEVICES, {"wlan-removal": plan}, "audit")
    assert {row.resolution for row in ledger.rows} == {"uncovered", "claimed"}
    assert {path for row in ledger.rows if row.target.device_mac == AP for path in row.uncovered_paths} == {
        ("vlan_id",)
    }


def test_switching_a_wlan_on_or_creating_one_is_not_a_lifecycle_change():
    enabled = wlan_change(before={"enabled": False}, after={"enabled": True})
    created = wlan_change(before={}, after={"enabled": True, "ssid": "corp"})

    assert WlanRemovalPlugin().plan(enabled, DEVICES) is None
    assert WlanRemovalPlugin().plan(created, DEVICES) is None


@pytest.mark.parametrize(
    ("overrides", "gap"),
    [
        ({"scope": "org", "site_id": None}, "Organization WLAN consumer resolution"),
        ({"mist_id": None}, "provider identity"),
        ({"site_id": None}, "provider identity"),
    ],
)
def test_an_unresolved_wlan_identity_is_a_visible_gap_and_claims_nothing(overrides, gap):
    plan = WlanRemovalPlugin().plan(wlan_change(**overrides), DEVICES)

    assert plan is not None
    assert plan.obligations == ()
    assert any(gap in text for text in plan.gaps)


def test_only_one_wlan_is_read_and_the_rest_stay_a_gap():
    changes = build_change_set(
        [
            ObjectChange(
                logical_object_id=f"wlan-{index}",
                scope="site",
                object_type="wlans",
                name=f"corp-{index}",
                version=2,
                before={"enabled": True},
                after={},
                site_id=SITE,
                mist_id=f"00000000-0000-0000-0000-00000000000{index}",
            )
            for index in (1, 2)
        ]
    )
    plan = WlanRemovalPlugin().plan(changes, DEVICES)

    assert plan.wlan_id == "00000000-0000-0000-0000-000000000001"
    assert {o.change_ref for o in plan.obligations} == {"A1"}
    assert any("further changed WLAN" in text for text in plan.gaps)


def test_a_wlan_with_no_access_point_in_the_cohort_claims_no_row():
    plan = WlanRemovalPlugin().plan(wlan_change(), [ExpectedDevice(mac=SWITCH, site_id=SITE, device_type="switch")])

    assert plan.obligations == ()
    assert any("no device row is claimed" in text for text in plan.gaps)


# -- wlan-removal: collection and evaluation -----------------------------------


async def test_the_session_reads_are_one_scoped_query_per_window_and_are_charged_to_the_plug_in():
    transport = FakeRuleTransport()
    _plan, _conclusion, bounded = await run(WlanRemovalPlugin(), wlan_change(), transport=transport)

    assert [path for path, _ in transport.reads] == [f"/api/v1/sites/{SITE}/clients/sessions/search"] * 2
    assert [params["wlan_id"] for _, params in transport.reads] == [WLAN, WLAN]
    assert [(params["start"], params["end"]) for _, params in transport.reads] == [
        (str(int(WINDOWS.before.start.timestamp())), str(int(WINDOWS.before.end.timestamp()))),
        (str(int(WINDOWS.after.start.timestamp())), str(int(WINDOWS.after.end.timestamp()))),
    ]
    assert bounded.budget.rule_reads == 2
    with pytest.raises(ReadRejectedError, match="spent its reads"):
        await WlanRemovalPlugin().collect(_plan, bounded)


async def test_a_previously_connected_client_that_disconnects_is_a_possible_disruption():
    disconnected = session(connect=(CHANGED_AT - timedelta(minutes=5)).timestamp(), disconnect=None)
    departure = session(
        connect=(CHANGED_AT - timedelta(minutes=5)).timestamp(),
        disconnect=(CHANGED_AT + timedelta(minutes=1)).timestamp(),
    )
    # The same session reported twice is one client, and a client that was never connected before is not affected.
    after = sessions(departure, departure, session(client=OTHER_CLIENT, connect=AS_OF.timestamp() - 5, disconnect=None))
    transport = FakeRuleTransport(
        lambda _path, params: sessions(disconnected) if params["start"] == BEFORE_START else after
    )
    _plan, conclusion, _ = await run(WlanRemovalPlugin(), wlan_change(), transport=transport)

    assert (conclusion.peak, conclusion.current) == ("warning", "warning")
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}
    assert [device.mac for device in conclusion.impacted_devices] == [AP]
    assert "1 of 1 client(s)" in conclusion.findings[0].text
    assert "causation are not established" in conclusion.findings[0].text
    assert CLIENT not in conclusion.model_dump_json()


async def test_an_unused_wlan_deletion_is_a_complete_observation_of_no_disruption():
    transport = FakeRuleTransport(sessions())
    plan, conclusion, _ = await run(WlanRemovalPlugin(), wlan_change(), transport=transport)
    ledger = build_ledger(wlan_change(), DEVICES, {"wlan-removal": plan}, "audit")

    assert (conclusion.peak, conclusion.current) == ("none", "none")
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}
    assert conclusion.impacted_devices == ()
    assert "Failed joins and unrecorded sessions are not covered" in conclusion.findings[0].text
    # Nothing but the deployment preconditions stands between this and complete coverage.
    statuses = ledger.rule_statuses("wlan-removal", conclusion.statuses)
    assert {status.status for status in statuses.values()} == {"satisfied"}


@pytest.mark.parametrize(
    ("result", "reason"),
    [
        (TransportError("Mist returned HTTP 503"), "read failed"),
        ({"results": [], "total": 3}, base.PARTIAL_REASON),
        ({"results": [{"mac": "x" * 2000, "note": "y" * 2000}], "total": 1}, base.DIGEST_REASON),
    ],
)
async def test_a_failed_partial_or_digested_collection_is_never_zero_usage(result, reason):
    transport = FakeRuleTransport(result)
    _plan, conclusion, _ = await run(WlanRemovalPlugin(), wlan_change(), transport=transport)

    assert {status.status for status in conclusion.statuses.values()} == {"unsatisfied"}
    assert all(reason.lower() in (status.reason or "").lower() for status in conclusion.statuses.values())
    assert (conclusion.peak, conclusion.current) == ("none", "none")


async def test_session_evidence_naming_another_wlan_cannot_answer_this_one():
    row = session(connect=CHANGED_AT.timestamp() - 5, disconnect=None) | {"wlan_id": OTHER_WLAN}
    transport = FakeRuleTransport(sessions(row))
    _plan, conclusion, _ = await run(WlanRemovalPlugin(), wlan_change(), transport=transport)

    assert {status.reason for status in conclusion.statuses.values()} == {"The session evidence named another WLAN"}


# -- wlan-auth -----------------------------------------------------------------


def auth_change(attribute: str = "auth", *, extra: dict | None = None):
    before = {attribute: {"type": "psk"}, "enabled": True} | (extra or {})
    after = {attribute: {"type": "eap"}, "enabled": True} | (extra or {})
    return wlan_change(before=before, after=after)


def test_wlan_auth_claims_the_authentication_attributes_and_nothing_else():
    changes = auth_change(extra={"vlan_id": 10})
    changes = build_change_set(
        [
            ObjectChange(
                logical_object_id="wlan-1",
                scope="site",
                object_type="wlans",
                name="corp",
                version=2,
                before={"auth": {"type": "psk"}, "vlan_id": 10},
                after={"auth": {"type": "eap"}, "vlan_id": 20},
                site_id=SITE,
                mist_id=WLAN,
            )
        ]
    )
    plan = WlanAuthPlugin().plan(changes, DEVICES)
    base.validate_plan(WlanAuthPlugin(), plan, changes)

    assert isinstance(plan, WlanAuthPlan)
    [auth] = [atom for atom in changes.atoms if atom.attribute == "auth"]
    assert {o.change_ref for o in plan.obligations} == {auth.id}
    ledger = build_ledger(changes, DEVICES, {"wlan-auth": plan}, "audit")
    assert {path for row in ledger.rows if row.target.device_mac == AP for path in row.uncovered_paths} == {
        ("vlan_id",)
    }


def test_a_deleted_wlan_is_a_lifecycle_change_not_an_authentication_change():
    assert WlanAuthPlugin().plan(wlan_change(before={"auth": {"type": "psk"}}, after={}), DEVICES) is None


async def test_a_client_that_authenticated_before_and_failed_after_is_a_disruption_that_can_recover():
    before = {
        "results": [auth_event(kind="CLIENT_AUTHENTICATED", at=CHANGED_AT - timedelta(minutes=1))],
        "total": 1,
    }
    after = {
        "results": [
            auth_event(kind="MARVIS_EVENT_CLIENT_AUTH_FAILURE", at=CHANGED_AT + timedelta(seconds=1)),
            auth_event(kind="CLIENT_AUTHENTICATED", at=CHANGED_AT + timedelta(seconds=30)),
            auth_event(
                kind="MARVIS_EVENT_CLIENT_AUTH_FAILURE", at=CHANGED_AT + timedelta(seconds=2), client=OTHER_CLIENT
            ),
        ],
        "total": 3,
    }
    transport = FakeRuleTransport(lambda _path, params: before if params["start"] == BEFORE_START else after)
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=transport)

    # One client authenticated before and failed after; the other never authenticated before, so it is not paired.
    assert (conclusion.peak, conclusion.current) == ("warning", "none")
    assert "1 client(s)" in conclusion.findings[0].text
    assert [device.mac for device in conclusion.impacted_devices] == [AP]
    assert CLIENT not in conclusion.model_dump_json()
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}


async def test_no_attempt_at_all_is_not_exercised_and_never_successful_authentication():
    transport = FakeRuleTransport({"results": [], "total": 0})
    plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=transport)

    assert {status.status for status in conclusion.statuses.values()} == {"not_exercised"}
    assert (conclusion.peak, conclusion.current) == ("none", "none")
    assert "No attempt is not successful authentication" in conclusion.findings[0].text
    ledger = build_ledger(auth_change(), DEVICES, {"wlan-auth": plan}, "audit")
    statuses = ledger.rule_statuses("wlan-auth", conclusion.statuses)
    assert {status.status for status in statuses.values()} == {"not_exercised"}


async def test_same_time_contradictory_outcomes_for_one_client_stay_unresolved():
    rows = {
        "results": [
            auth_event(kind="CLIENT_AUTHENTICATED", at=CHANGED_AT + timedelta(seconds=1)),
            auth_event(kind="MARVIS_EVENT_CLIENT_AUTH_FAILURE", at=CHANGED_AT + timedelta(seconds=1)),
        ],
        "total": 2,
    }
    transport = FakeRuleTransport(rows)
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=transport)

    assert {status.reason for status in conclusion.statuses.values()} == {
        "Same-time contradictory authentication outcomes remain unresolved"
    }


async def test_an_event_without_a_usable_client_identity_cannot_pair_clients():
    rows = {"results": [auth_event(kind="CLIENT_AUTHENTICATED", at=CHANGED_AT, client="not-a-mac")], "total": 1}
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=FakeRuleTransport(rows))

    assert all("client identity" in (status.reason or "") for status in conclusion.statuses.values())


# -- the plug-in boundary ------------------------------------------------------


def test_the_registry_declares_read_allowances_within_the_attempts_own_budget():
    allowances = base.rule_allowances(PLUGINS)

    assert allowances == {"dns": 0, "switch-port": 3, "wlan-auth": 2, "wlan-removal": 2}
    assert sum(allowances.values()) <= MAX_RULE_READS
    assert [plugin.id for plugin in PLUGINS] == sorted(plugin.id for plugin in PLUGINS)
    assert all(plugin.version and plugin.agent_hint for plugin in PLUGINS)
    # The hints are the ported playbooks; they share the prompt with everything else, so each one stays short.
    assert all(len(plugin.agent_hint) <= 1_000 for plugin in PLUGINS)


class BrokenPluginError(RuntimeError):
    """What a plug-in raises in these tests, so the boundary has something real to isolate."""

    def __init__(self, phase: str) -> None:
        super().__init__(f"{phase} exploded\nwith a second line")


class Broken:
    """A plug-in that fails wherever a test asks it to."""

    id = "broken"
    version = "1"
    max_reads = 0
    agent_hint = "never trusted"

    def __init__(self, phase: str) -> None:
        self.phase = phase

    def plan(self, change, devices):  # noqa: ARG002 - the plan is fixed, the failure is the point
        if self.phase == "plan":
            raise BrokenPluginError(self.phase)
        return RulePlan()

    async def collect(self, plan, reader):  # noqa: ARG002 - see plan
        if self.phase == "collect":
            raise BrokenPluginError(self.phase)
        return []

    def evaluate(self, plan, evidence):  # noqa: ARG002 - see plan
        if self.phase == "evaluate":
            raise BrokenPluginError(self.phase)
        return Conclusion()


@pytest.mark.parametrize("phase", ["plan", "collect", "evaluate"])
async def test_one_failing_plug_in_is_one_bounded_gap_and_never_stops_the_others(phase):
    broken = Broken(phase)
    outcome = await base.run_rules([broken, WlanRemovalPlugin()], wlan_change(), DEVICES, reader())

    [gap] = outcome.conclusions["broken"].gaps
    failed = {"plan": base.PLAN_FAILED, "collect": base.COLLECTION_FAILED, "evaluate": base.EVALUATION_FAILED}[phase]
    assert gap.startswith(f"broken {failed}")
    assert "\n" not in gap  # a bounded reason is one line, whatever the plug-in raised
    assert ("broken" in outcome.plans) == (phase != "plan")
    # The other plug-in still planned, collected and concluded.
    assert outcome.plans["wlan-removal"].obligations
    assert outcome.conclusions["wlan-removal"].statuses


async def test_a_plan_that_claims_what_the_change_did_not_do_is_that_plug_ins_gap_alone():
    class Overreaching(Broken):
        def plan(self, change, devices):
            good = WlanRemovalPlugin().plan(change, devices)
            return RulePlan(
                obligations=tuple(
                    o.model_copy(update={"owner": "broken", "paths": (("never_changed",),)}) for o in good.obligations
                )
            )

    outcome = await base.run_rules([Overreaching("none")], wlan_change(), DEVICES, reader())

    assert outcome.plans == {}
    assert any("planning failed" in gap for gap in outcome.conclusions["broken"].gaps)


async def test_collection_failures_still_leave_every_obligation_its_own_reason():
    class Refusing(WlanRemovalPlugin):
        async def collect(self, plan, reader):  # noqa: ARG002 - the refusal is the point
            raise BrokenPluginError(REFUSED)

    outcome = await base.run_rules([Refusing()], wlan_change(), DEVICES, reader())

    conclusion = outcome.conclusions["wlan-removal"]
    assert any("collection failed" in gap for gap in conclusion.gaps)
    assert {status.status for status in conclusion.statuses.values()} == {"unsatisfied"}
    assert {status.reason for status in conclusion.statuses.values()} == {base.NOT_READ_REASON}


@pytest.mark.parametrize(
    ("overrides", "gap"),
    [
        ({"scope": "org", "site_id": None}, "Organization WLAN consumer resolution"),
        ({"mist_id": None}, "provider identity"),
    ],
)
def test_wlan_auth_reports_the_same_unresolved_identities_as_a_gap(overrides, gap):
    changes = wlan_change(before={"auth": {"type": "psk"}}, after={"auth": {"type": "eap"}}, **overrides)
    plan = WlanAuthPlugin().plan(changes, DEVICES)

    assert plan.obligations == ()
    assert any(gap in text for text in plan.gaps)


def test_wlan_auth_reads_one_wlan_and_claims_no_row_without_an_access_point():
    changes = build_change_set(
        [
            ObjectChange(
                logical_object_id=f"wlan-{index}",
                scope="site",
                object_type="wlans",
                name=f"corp-{index}",
                version=2,
                before={"auth_servers": []},
                after={"auth_servers": [{"host": "10.0.0.1"}]},
                site_id=SITE,
                mist_id=f"00000000-0000-0000-0000-00000000000{index}",
            )
            for index in (1, 2)
        ]
    )
    plan = WlanAuthPlugin().plan(changes, [ExpectedDevice(mac=SWITCH, site_id=SITE, device_type="switch")])

    assert plan.obligations == ()
    assert any("further WLAN(s) with changed authentication" in text for text in plan.gaps)
    assert any("no device row is claimed" in text for text in plan.gaps)


async def test_authentication_evidence_naming_another_wlan_cannot_answer_this_one():
    rows = {
        "results": [
            auth_event(kind="CLIENT_AUTHENTICATED", at=CHANGED_AT, wlan=OTHER_WLAN),
            # An event of no authentication outcome is ignored rather than counted either way.
            auth_event(kind="CLIENT_ROAM", at=CHANGED_AT),
        ],
        "total": 2,
    }
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=FakeRuleTransport(rows))

    assert {status.reason for status in conclusion.statuses.values()} == {
        "The authentication evidence named another WLAN"
    }


async def test_an_event_that_is_no_authentication_outcome_is_neither_an_attempt_nor_a_failure():
    rows = {"results": [auth_event(kind="CLIENT_ROAM", at=CHANGED_AT)], "total": 1}
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=FakeRuleTransport(rows))

    assert {status.status for status in conclusion.statuses.values()} == {"not_exercised"}


def test_the_declared_allowances_must_fit_the_attempt():
    class Greedy(Broken):
        max_reads = MAX_RULE_READS + 1

    with pytest.raises(base.PluginError, match="above the attempt"):
        base.rule_allowances([*PLUGINS, Greedy("none")])


def test_a_plan_owned_by_another_plug_in_or_naming_another_change_is_refused():
    changes = wlan_change()
    plugin = WlanRemovalPlugin()
    plan = plugin.plan(changes, DEVICES)

    foreign = plan.model_copy(
        update={"obligations": tuple(o.model_copy(update={"owner": "dns"}) for o in plan.obligations)}
    )
    with pytest.raises(base.PluginError, match="owned by dns"):
        base.validate_plan(plugin, foreign, changes)

    invented = plan.model_copy(
        update={"obligations": tuple(o.model_copy(update={"change_ref": "A99"}) for o in plan.obligations)}
    )
    with pytest.raises(base.PluginError, match="not an atom of this change"):
        base.validate_plan(plugin, invented, changes)


async def test_a_conclusion_may_only_answer_its_own_obligations_and_cite_what_it_collected():
    changes = wlan_change()
    plugin = WlanRemovalPlugin()
    plan = plugin.plan(changes, DEVICES)
    status = ObligationStatus(status="satisfied", evidence_ids=("E7",))

    with pytest.raises(base.PluginError, match="does not own"):
        base.validate_conclusion(plugin, plan, Conclusion(statuses={"O99": status}), [])
    with pytest.raises(base.PluginError, match="cited evidence it did not collect"):
        base.validate_conclusion(plugin, plan, Conclusion(statuses={"O1": status}), [])


async def test_a_plug_in_given_another_plug_ins_plan_refuses_to_act_on_it():
    for plugin, other in ((WlanAuthPlugin(), WlanRemovalPlan()), (WlanRemovalPlugin(), WlanAuthPlan())):
        with pytest.raises(base.PluginError, match="another plug-in's plan"):
            plugin.evaluate(other, [])
        with pytest.raises(base.PluginError, match="another plug-in's plan"):
            await plugin.collect(other, reader())


async def test_a_client_that_kept_authenticating_is_counterevidence_not_an_absence():
    kept = {
        "results": [
            auth_event(kind="CLIENT_AUTH_ASSOCIATION", at=CHANGED_AT - timedelta(minutes=1)),
            auth_event(kind="CLIENT_AUTH_REASSOCIATION", at=CHANGED_AT + timedelta(seconds=5)),
        ],
        "total": 2,
    }
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=FakeRuleTransport(kept))

    assert (conclusion.peak, conclusion.current) == ("none", "none")
    assert {status.status for status in conclusion.statuses.values()} == {"satisfied"}
    assert "kept authenticating after it" in conclusion.findings[0].text


async def test_a_result_without_the_rows_it_should_carry_is_never_zero_usage():
    _plan, conclusion, _ = await run(WlanRemovalPlugin(), wlan_change(), transport=FakeRuleTransport({"total": 0}))

    assert {status.reason for status in conclusion.statuses.values()} == {"The result held no results"}


async def test_a_plug_in_with_nothing_it_can_read_makes_no_read_at_all():
    plan = WlanRemovalPlugin().plan(wlan_change(mist_id=None), DEVICES)
    auth = WlanAuthPlugin().plan(
        wlan_change(before={"auth": {"a": 1}}, after={"auth": {"a": 2}}, mist_id=None), DEVICES
    )
    transport = FakeRuleTransport()
    bounded = reader(transport)

    assert await WlanRemovalPlugin().collect(plan, bounded) == []
    assert await WlanAuthPlugin().collect(auth, bounded) == []
    assert transport.reads == []
    assert bounded.budget.rule_reads == 0


def test_a_wlan_changed_without_an_authentication_attribute_is_not_this_rules_change():
    assert WlanAuthPlugin().plan(wlan_change(before={"vlan_id": 10}, after={"vlan_id": 20}), DEVICES) is None


@pytest.mark.parametrize("result", [TransportError("Mist returned HTTP 503"), {"results": [], "total": 2}])
async def test_authentication_evidence_that_cannot_be_relied_on_is_not_a_quiet_wlan(result):
    _plan, conclusion, _ = await run(WlanAuthPlugin(), auth_change(), transport=FakeRuleTransport(result))

    assert {status.status for status in conclusion.statuses.values()} == {"unsatisfied"}
    assert (conclusion.peak, conclusion.current) == ("none", "none")
