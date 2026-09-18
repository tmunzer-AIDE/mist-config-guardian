"""The DNT-NTR replay: the recorded audit driven through Guardian's production attempt path.

The three fixtures in ``fixtures/guardian/`` are the audit of 2026-09-16 reconstructed from production API
projections and pseudonymized (Task 1). This module turns them back into the inputs one attempt loads and runs
:func:`services.guardian.execute_attempt` over them, which is the production phase machine: the real change
compiler, rule plug-ins, coverage ledger, deployment pairing, monitoring replay, evidence registry and verdict
composition. Only the two external boundaries are stood in for. No Mist API, no MCP server and no model
provider is reached, and the fakes record every call so the replay can assert that none was made.

What is asserted is what the frozen verification record implies, not what the engine happens to produce:

- ``dns_attribute_semantics`` records ``org:networktemplates`` ``dns_servers`` as
  ``management_and_client_resolution`` for switches, so the ``dns`` plug-in claims the three switch rows with one
  infrastructure obligation (``switch-health``, ``empty_policy=incomplete``) and one client obligation
  (``switch-stc``, ``empty_policy=not_exercised``) each, and the core adds one deployment precondition per
  claimed switch. No plug-in targets the three APs or the gateway and no exclusion has a schema basis, so those
  four rows stay uncovered.
- ``device_event_ordering`` is ``same_second_ambiguous``: provider times are compared at one-second precision, so
  the 242 ms audit anchor may not push a device into deployment ``unknown``.
- ``sw_configured_emission`` is ``unknown``, so both variants are replayed: as recorded, where no switch has a
  confirming outcome, and with the three confirming outcomes added.
"""

# The fake transports mirror the Reader's protocols, whose ``timeout`` is an HTTP request bound, not an asyncio one.
# ruff: noqa: ARG002, ASYNC109

import json
import time
from datetime import datetime
from typing import Any

import pytest
from beanie import PydanticObjectId

from guardian_verification import decision, dns_mappings, load_fixture, load_verification
from mist_config_guardian_backend.guardian.agent import NO_CAPABILITY
from mist_config_guardian_backend.guardian.change import ObjectChange
from mist_config_guardian_backend.guardian.contracts import FINAL_FORCED, FINAL_MINIMUM, Verdict
from mist_config_guardian_backend.guardian.deployment import NO_OUTCOME_REASON, PAIRING_BOUND, DeviceEventReceipt
from mist_config_guardian_backend.guardian.monitoring import MonitoringRecord
from mist_config_guardian_backend.guardian.plugins import dns
from mist_config_guardian_backend.guardian.reader import TransportError
from mist_config_guardian_backend.models.monitoring import DeviceType, MonitoringSession, SleObservation
from mist_config_guardian_backend.services.guardian import (
    AttemptInputs,
    AttemptOutcome,
    AttemptTools,
    device_receipt,
    execute_attempt,
    monitoring_record,
)
from mist_config_guardian_backend.snapshots.registry import DEFAULT_IGNORED_FIELDS

CHANGE = load_fixture("dnt_ntr_change.json")
EVENTS = load_fixture("dnt_ntr_device_events.json")
MONITORING = load_fixture("dnt_ntr_monitoring.json")

ORG = PydanticObjectId("00000000000000000000a001")
AUDIT: str = CHANGE["audit"]["audit_id"]
SITE: str = CHANGE["site_id"]


def at(value: str) -> datetime:
    return datetime.fromisoformat(value)


ANCHOR = at(CHANGE["audit"]["occurred_at"])
# The final run's instant: every linked session is terminal and the final minimum has passed.
AS_OF = max(at(session["completed_at"]) for session in MONITORING["sessions"])
SWITCHES = tuple(row["device_mac"] for row in CHANGE["devices"] if row["device_type"] == "switch")
UNTARGETED = tuple(row["device_mac"] for row in CHANGE["devices"] if row["device_type"] != "switch")
# The APs reported their own confirmation in this second; a switch confirmation would arrive in the same shape.
CONFIRMED_AT = "2026-09-16T04:41:37Z"

# What a dual-use switch resolver is judged by, per the design's DNS rule: the device's own reachability and
# health, where no data is a hole, and the clients' connection experience, where no traffic means the setting was
# never exercised. The names are written out here so a change to the plug-in's choice fails this replay.
INFRASTRUCTURE_METRIC = "switch-health"
CLIENT_METRIC = "switch-stc"

# The projections record which attributes the audit changed, never their values, so the replay supplies one
# placeholder resolver address per side. Only the changed path decides the mapping, and ``modified_time`` is a
# registry-ignored metadata field that forms no atom.
BEFORE: dict[str, Any] = {"dns_servers": ["10.0.0.1"], "modified_time": 1_758_000_000}
AFTER: dict[str, Any] = {"dns_servers": ["10.0.0.2"], "modified_time": 1_758_000_100}


# -- the recorded audit, as one attempt's inputs ---------------------------------------------------------------------


def changes() -> tuple[ObjectChange, ...]:
    (changed,) = CHANGE["changed_objects"]
    assert sorted(changed["changed_fields"]) == sorted(BEFORE) == sorted(AFTER)
    return (
        ObjectChange(
            logical_object_id=changed["logical_object_id"],
            scope=changed["scope"],
            object_type=changed["object_type"],
            name=changed["object_name"],
            version=1,
            before=BEFORE,
            after=AFTER,
        ),
    )


def confirmations() -> list[dict[str, Any]]:
    """The ``SW_CONFIGURED`` receipts the recorded audit never carried, in the shape the APs' own outcomes have."""
    return [
        {
            "receipt_id": f"00000000000000000000f00{index}",
            "received_at": "2026-09-16T04:41:49.300000Z",
            "event_type": "SW_CONFIGURED",
            "device_type": "switch",
            "device_mac": mac,
            "occurred_at": CONFIRMED_AT,
            "audit_id": None,
        }
        for index, mac in enumerate(SWITCHES, start=1)
    ]


def receipts(rows: list[dict[str, Any]]) -> tuple[DeviceEventReceipt, ...]:
    """Each recorded device event through the production normalizer, as a stored receipt row reaches it."""
    built = []
    for row in rows:
        receipt = device_receipt(
            {
                "_id": row["receipt_id"],
                "created_at": at(row["received_at"]),
                "audit_id": row["audit_id"],
                "deployment": {
                    "device_mac": row["device_mac"],
                    "site_id": EVENTS["site_id"],
                    "event_type": row["event_type"],
                    "occurred_at": at(row["occurred_at"]),
                },
            }
        )
        assert receipt is not None
        built.append(receipt)
    return tuple(built)


def observation(row: dict[str, Any], side: str, captured_at: datetime) -> SleObservation:
    """One recorded SLE sample. The projection kept only the baseline and the latest values of each metric."""
    metrics = {item["name"]: item for item in row["metrics"]}
    state = f"{side}_state"
    return SleObservation(
        captured_at=captured_at,
        scope="site",
        scope_id=SITE,
        values={name: item[side] for name, item in metrics.items() if item[state] == "measured"},
        no_data=[name for name, item in metrics.items() if item[state] == "no_data"],
        requested_metrics=sorted(metrics),
        metric_states={name: item[state] for name, item in metrics.items()},
    )


def sessions() -> tuple[MonitoringRecord, ...]:
    """Every recorded monitoring session, through the production ``MonitoringSession`` to record converter."""
    records = []
    for row in MONITORING["sessions"]:
        session = MonitoringSession.model_construct(
            id=PydanticObjectId(row["session_id"]),
            organization_id=ORG,
            audit_ids=list(row["audit_ids"]),
            receipt_ids=[],
            timeline=[],
            site_id=MONITORING["site_id"],
            device_mac=row["device_mac"],
            device_name=row["device_name"],
            device_type=DeviceType(row["device_type"]),
            active=row["monitoring_state"] != "completed",
            created_at=at(row["detected_at"]),
            completed_at=at(row["completed_at"]),
            baseline=observation(row, "baseline", at(row["snapshot_at"])),
            observations=[observation(row, "latest", at(row["completed_at"]))],
            incidents=[],
            device_comparisons=[],
            device_findings=[],
        )
        record = monitoring_record(session)
        assert record is not None
        records.append(record)
    return tuple(records)


def scenario(*, confirmed: bool = False) -> AttemptInputs:
    rows = [*EVENTS["receipts"], *(confirmations() if confirmed else [])]
    return AttemptInputs(
        organization_id=ORG,
        audit_id=AUDIT,
        received_at=min(at(row["received_at"]) for row in EVENTS["receipts"]),
        audit_time=ANCHOR,
        changes=changes(),
        receipts=receipts(rows),
        sessions=sessions(),
    )


# -- the two external boundaries, stood in for -------------------------------------------------------------------


class FakeRuleTransport:
    """Mist, absent. The DNT-NTR change plans no rule read, so any call here is a replay defect."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def fetch(self, path: str, params: Any, *, timeout: float, max_bytes: int) -> Any:
        self.calls.append(path)
        msg = "no Mist API is reachable in a replay"
        raise TransportError(msg)


class FakeMcpTransport:
    """The MCP server, absent. Only the agent reaches it, and this replay's agent is skipped."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def list_tools(self, *, timeout: float, max_bytes: int) -> dict[str, Any]:
        self.calls.append("tools/list")
        return {"tools": []}

    async def call_tool(self, name: str, arguments: Any, *, timeout: float, max_bytes: int) -> dict[str, Any]:
        self.calls.append(name)
        msg = "no MCP server is reachable in a replay"
        raise TransportError(msg)


class FakeModel:
    """The provider, stood in for by canned replies. An empty list is a provider that answers nothing."""

    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.prompts: list[tuple[str, str]] = []

    async def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if not self.replies:
            msg = "The fake provider ran out of replies"
            raise AssertionError(msg)
        return self.replies.pop(0)


class Boundaries:
    """One replay's fakes, so a test can assert what was and was not called."""

    def __init__(self, *replies: str) -> None:
        self.rules = FakeRuleTransport()
        self.mcp = FakeMcpTransport()
        self.model = FakeModel(*replies) if replies else None

    def tools(self) -> AttemptTools:
        # Without a capability record the production builder skips the agent, and ``structured_output_capability``
        # is recorded ``inconclusive``: no provider was ever probed.
        return AttemptTools(
            rule_transport=self.rules,
            mcp_transport=self.mcp,
            model_client=self.model,
            skip_reason=None if self.model is not None else NO_CAPABILITY,
        )


async def replay(
    *, confirmed: bool = False, as_of: datetime = AS_OF, boundaries: Boundaries | None = None
) -> AttemptOutcome:
    """One attempt over the recorded audit, through the production phase machine."""
    outer = boundaries or Boundaries()
    outcome = await execute_attempt(
        scenario(confirmed=confirmed), tools=outer.tools(), started=time.monotonic(), as_of=as_of
    )
    assert outcome.state == "succeeded", outcome.failure_reason
    return outcome


def obligations(outcome: AttemptOutcome) -> dict[str, tuple[str, str, str | None, str]]:
    """Every obligation as ``id -> (kind, device, metric, status)``, which is what the expectation names."""
    return {
        item.obligation.id: (
            item.obligation.kind,
            item.obligation.target.device_mac or "",
            item.obligation.metric,
            item.status.status,
        )
        for item in outcome.fields["obligations"]
    }


def expected_obligations(*, confirmed: bool) -> dict[str, tuple[str, str, str | None, str]]:
    """What the verified mapping implies, built from the record rather than from the run.

    Numbering follows the ledger's own order: the plug-in's obligations (by atom, MAC, metric and policy), then
    one deployment precondition per claimed device by MAC, then one unsatisfied observation per uncovered row.
    """
    infrastructure, client = INFRASTRUCTURE_METRIC, CLIENT_METRIC
    metrics = {row["device_mac"]: {item["name"]: item for item in row["metrics"]} for row in MONITORING["sessions"]}
    expected: dict[str, tuple[str, str, str | None, str]] = {}
    for index, mac in enumerate(sorted(SWITCHES)):
        # incomplete: no data in either window is a hole. not_exercised: no client traffic never tried the setting.
        infrastructure_status = _status(metrics[mac][infrastructure], "incomplete")
        expected[f"O{2 * index + 1}"] = ("monitoring", mac, infrastructure, infrastructure_status)
        expected[f"O{2 * index + 2}"] = ("monitoring", mac, client, _status(metrics[mac][client], "not_exercised"))
    for index, mac in enumerate(sorted(SWITCHES)):
        expected[f"O{2 * len(SWITCHES) + index + 1}"] = (
            "deployment",
            mac,
            None,
            "satisfied" if confirmed else "unsatisfied",
        )
    for index, mac in enumerate(sorted(UNTARGETED)):
        expected[f"O{3 * len(SWITCHES) + index + 1}"] = ("rule", mac, None, "unsatisfied")
    return expected


def _status(metric: dict[str, Any], empty_policy: str) -> str:
    """The recorded metric's obligation status under the treatment table: both states decide it."""
    states = (metric["baseline_state"], metric["latest_state"])
    if states == ("measured", "measured"):
        return "satisfied" if metric["comparable"] else "unsatisfied"
    if states == ("no_data", "no_data"):
        return "not_exercised" if empty_policy == "not_exercised" else "unsatisfied"
    return "unsatisfied"


# -- the record this replay is measured against --------------------------------------------------------------------


def test_the_replay_asserts_the_mapping_the_verification_record_froze() -> None:
    record = load_verification()
    (changed,) = CHANGE["changed_objects"]
    (mapping,) = dns_mappings(f"{changed['scope']}:{changed['object_type']}", "dns_servers")

    assert mapping["semantics"] == "management_and_client_resolution"
    assert mapping["device_types"] == ["switch"]
    assert decision(record, "sw_configured_emission")["result"] == "unknown"
    assert decision(record, "device_event_ordering")["result"] == "same_second_ambiguous"
    # The agent contributes nothing here: no provider was ever probed, so no capability record exists.
    assert decision(record, "structured_output_capability")["result"] == "inconclusive"
    assert [field for field in changed["changed_fields"] if field in DEFAULT_IGNORED_FIELDS] == ["modified_time"]
    assert AS_OF - ANCHOR >= FINAL_MINIMUM
    assert dns.INFRASTRUCTURE_METRICS["switch"] == INFRASTRUCTURE_METRIC
    assert dns.CLIENT_METRICS["switch"] == CLIENT_METRIC


# -- the outcome ----------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("confirmed", [False, True], ids=["as_recorded", "sw_configured_added"])
async def test_the_dnt_ntr_audit_replays_to_the_verified_mappings_outcome(confirmed: bool) -> None:  # noqa: FBT001 - a pytest parameter
    outcome = await replay(confirmed=confirmed)
    verdict = outcome.fields["verdict"]
    assert isinstance(verdict, Verdict)

    # The dual-use mapping claims the switches, nothing claims the APs or the gateway, and no input reaches
    # warning, so the base band decides both projections and nothing raises a floor above it.
    assert (verdict.peak, verdict.current) == ("info", "info")
    assert verdict.coverage == "partial"
    assert verdict.confidence == "low"
    assert verdict.recovery == "none"
    assert verdict.impacted_devices == ()
    assert verdict.sources == ("monitoring", "deployment", "rule:dns")
    # The only gap is the agent's absence: no provider was ever probed, so no capability record exists.
    assert [gap.source for gap in verdict.gaps] == ["agent"]
    assert NO_CAPABILITY in verdict.gaps[0].text
    assert obligations(outcome) == expected_obligations(confirmed=confirmed)


@pytest.mark.parametrize("confirmed", [False, True], ids=["as_recorded", "sw_configured_added"])
async def test_the_unsatisfied_obligations_are_named_one_by_one(confirmed: bool) -> None:  # noqa: FBT001 - a pytest parameter
    outcome = await replay(confirmed=confirmed)
    unsatisfied = {name: row for name, row in obligations(outcome).items() if row[3] == "unsatisfied"}

    # switch-health has no data in either window on all three switches, and its empty policy is `incomplete`.
    assert {row[1] for row in unsatisfied.values() if row[2] == INFRASTRUCTURE_METRIC} == set(SWITCHES)
    # The four untargeted rows: no plug-in claims them and no exclusion has a schema basis.
    assert {row[1] for row in unsatisfied.values() if row[0] == "rule"} == set(UNTARGETED)
    # Confirming the switches is the only difference between the two variants.
    assert {row[1] for row in unsatisfied.values() if row[0] == "deployment"} == (set() if confirmed else set(SWITCHES))


async def test_a_client_metric_with_no_traffic_is_not_exercised_rather_than_satisfied() -> None:
    outcome = await replay()
    client = {row[1]: row[3] for row in obligations(outcome).values() if row[2] == CLIENT_METRIC}
    recorded = {
        row["device_mac"]: {item["name"]: item for item in row["metrics"]}
        for row in MONITORING["sessions"]
        if row["device_type"] == "switch"
    }

    assert client == {
        mac: "not_exercised" if recorded[mac][CLIENT_METRIC]["baseline_state"] == "no_data" else "satisfied"
        for mac in SWITCHES
    }
    assert "not_exercised" in client.values()


# -- the two invariants the record fixes, which hold for any mapping -------------------------------------------------


def deployment_rows(outcome: AttemptOutcome) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The recorded deployment pairing: the rows it kept, and the devices it counted instead.

    Pairing records full rows only for a device with an unsatisfied precondition or a deployment warning; every
    other device is counted under ``<precondition>:<peak>``. A device counted ``satisfied:none`` was confirmed,
    because only an unambiguously configured trigger of this audit satisfies a precondition.
    """
    (item,) = [row for row in outcome.fields["evidence"] if row.source == "deployment"]
    return item.payload["rows"], item.payload["omitted"]


@pytest.mark.parametrize("confirmed", [False, True], ids=["as_recorded", "sw_configured_added"])
async def test_no_device_becomes_deployment_unknown_at_second_precision(confirmed: bool) -> None:  # noqa: FBT001 - a pytest parameter
    outcome = await replay(confirmed=confirmed)
    anchor = outcome.fields["anchor"]
    assert (anchor.source, anchor.changed_at) == ("audit", ANCHOR)
    assert anchor.changed_at.microsecond == 242_000
    rows = {row.target.device_mac for row in outcome.fields["ledger"]}
    assert rows == {row["device_mac"] for row in CHANGE["devices"]}

    paired, omitted = deployment_rows(outcome)
    confirmed_devices = {row["device_mac"] for row in EVENTS["receipts"] if row["event_type"].endswith("_CONFIGURED")}
    if confirmed:
        confirmed_devices |= set(SWITCHES)

    # Every device the legacy millisecond comparison would have left without a trigger has one, in the anchor's
    # own second, and every recorded confirmation was paired with it.
    assert omitted == {"satisfied:none": len(confirmed_devices)}
    assert {row["mac"] for row in paired} == {row["device_mac"] for row in CHANGE["devices"]} - confirmed_devices
    for row in paired:
        assert row["trigger"] == "SW_CONFIG_CHANGED_BY_USER"
        assert at(row["triggered_at"]) == ANCHOR.replace(microsecond=0)
        assert (row["state"], row["reason"]) == ("unknown", NO_OUTCOME_REASON)
        assert row["precondition"] == "unsatisfied"


async def test_every_targeted_switch_without_a_confirming_outcome_is_unsatisfied() -> None:
    outcome = await replay()
    deployment = {row[1]: row[3] for row in obligations(outcome).values() if row[0] == "deployment"}

    assert set(deployment) == set(SWITCHES)
    assert set(deployment.values()) == {"unsatisfied"}
    assert not [row for row in EVENTS["receipts"] if row["event_type"] == "SW_CONFIGURED"]


async def test_confirming_the_switches_satisfies_their_preconditions_within_the_pairing_bound() -> None:
    outcome = await replay(confirmed=True)
    deployment = {row[1]: row[3] for row in obligations(outcome).values() if row[0] == "deployment"}

    assert set(deployment.values()) == {"satisfied"}
    assert at(CONFIRMED_AT) - ANCHOR.replace(microsecond=0) <= PAIRING_BOUND
    # Coverage stays partial even so: the APs and the gateway are still uncovered.
    assert outcome.fields["verdict"].coverage == "partial"


# -- the boundaries ---------------------------------------------------------------------------------------------


async def test_the_replay_reaches_no_provider_no_mcp_server_and_no_mist_api() -> None:
    boundaries = Boundaries()
    outcome = await replay(boundaries=boundaries)

    assert boundaries.rules.calls == []
    assert boundaries.mcp.calls == []
    assert boundaries.model is None
    assert outcome.fields["agent"].concluded is False
    assert outcome.fields["agent"].reason == NO_CAPABILITY
    assert outcome.fields["budget"].model_turns == 0
    assert outcome.fields["budget"].mcp_calls == 0
    assert outcome.fields["budget"].rule_reads == 0


async def test_a_forced_final_replays_the_same_outcome_from_the_same_terminal_sessions() -> None:
    forced = await replay(as_of=ANCHOR + FINAL_FORCED)
    natural = await replay()

    assert forced.fields["verdict"].peak == natural.fields["verdict"].peak
    assert forced.fields["verdict"].coverage == natural.fields["verdict"].coverage
    assert obligations(forced) == obligations(natural)


async def test_a_concurring_agent_report_raises_only_confidence() -> None:
    """The provider boundary, driven. Rule 3 lets a cited report contribute; rule 5 is all it can change here."""
    report = json.dumps(
        {
            "action": "report",
            "peak_impact": "info",
            "current_impact": "info",
            "confidence": "low",
            "summary": "The switches' own resolver was never observed and no client experience moved.",
            "evidence": ["E2"],
        }
    )
    boundaries = Boundaries(report)
    outcome = await replay(boundaries=boundaries)
    verdict = outcome.fields["verdict"]
    (cited,) = [item for item in outcome.fields["evidence"] if item.id == "E2"]

    assert cited.source == "monitoring"
    assert (cited.kind, cited.citable) == ("service_health", True)
    assert boundaries.model is not None
    assert len(boundaries.model.prompts) == 1
    assert outcome.fields["agent"].concluded is True
    # The deterministic outcome is untouched; only rule 5's concurrence raises confidence.
    assert (verdict.peak, verdict.current, verdict.coverage) == ("info", "info", "partial")
    assert verdict.confidence == "medium"
    # Rule 7: the base band decided both projections, so the coverage inputs are named and the agent is not.
    assert verdict.sources == ("monitoring", "deployment", "rule:dns")
    assert verdict.gaps == ()
