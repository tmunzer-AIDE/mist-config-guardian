"""Guardian's orchestrator away from MongoDB: the mapping, the trigger table and one attempt's phase machine.

The fenced tick itself is exercised against a real server in ``test_guardian_runtime_mongo.py``; everything here
either needs no collection at all or stands one in, so the phases, budgets and failure isolation stay fast to run.
"""

# The fake transports mirror the Reader's protocols, whose ``timeout`` is an HTTP bound, not an asyncio one, and
# the orchestrator's own publication text is asserted through its private helper.
# ruff: noqa: ARG002, ASYNC109, SLF001

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.guardian.agent import (
    NO_CAPABILITY,
    NO_MCP_ENDPOINT,
    NO_RUNTIME,
    ModelError,
)
from mist_config_guardian_backend.guardian.change import ObjectChange, build_change_set
from mist_config_guardian_backend.guardian.contracts import (
    EARLY_CUTOFF,
    FINAL_FORCED,
    FINAL_MINIMUM,
    RECHECK_DELAY,
    Gap,
    Verdict,
)
from mist_config_guardian_backend.guardian.deployment import DeviceEventReceipt, outcome_kind
from mist_config_guardian_backend.guardian.evidence import (
    CHANGE_VIEW_BUDGET,
    CONCLUSIONS_BUDGET,
    LEDGER_VIEW_BUDGET,
    STEPS_BUDGET,
    json_size,
)
from mist_config_guardian_backend.guardian.reader import TransportError
from mist_config_guardian_backend.guardian.repository import RUN_OUTCOME_FIELDS
from mist_config_guardian_backend.impact.deployment import normalize_deployment
from mist_config_guardian_backend.models.guardian import GuardianInvestigation
from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    MonitoringTimelineEvent,
    SleObservation,
)
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization
from mist_config_guardian_backend.models.telemetry import (
    DeviceStateComparison,
    DeviceStateFinding,
    DeviceStateObservation,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import guardian as service
from mist_config_guardian_backend.services.guardian import (
    AGENT_PHASE,
    RULE_PHASE,
    AttemptInputs,
    AttemptTools,
    GuardianService,
    SupersededObject,
    _status_reason,
    degraded,
    device_receipt,
    due_kind,
    execute_attempt,
    mask_secrets,
    monitoring_record,
    protected_configuration,
)
from mist_config_guardian_backend.services.impact_investigations import ImpactInvestigationService
from mist_config_guardian_backend.services.monitoring import MonitoringPollService
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.tasks import monitoring as task

ORG = PydanticObjectId()
AUDIT = "audit-1"
NOW = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
MAC = "5c5b350a0b01"
SITE = "20000000-0000-4000-8000-000000000001"
TEMPLATE = "00000000000000000000c001"


def vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", database_enabled=False))


def root(**overrides: Any) -> GuardianInvestigation:
    values: dict[str, Any] = {
        "id": PydanticObjectId(),
        "organization_id": ORG,
        "audit_id": AUDIT,
        "changed_at": NOW,
        "anchor_known": True,
        "status": "waiting",
        "next_check_at": NOW + RECHECK_DELAY,
    }
    return GuardianInvestigation.model_construct(**(values | overrides))


def session(**overrides: Any) -> MonitoringSession:
    values: dict[str, Any] = {
        "id": PydanticObjectId(),
        "organization_id": ORG,
        "audit_ids": [AUDIT],
        "receipt_ids": [],
        "timeline": [],
        "site_id": SITE,
        "device_mac": MAC,
        "device_name": "SEA-SW-1",
        "device_type": DeviceType.SWITCH,
        "active": False,
        "created_at": NOW,
        "observations": [],
        "incidents": [],
        "device_comparisons": [],
        "device_findings": [],
    }
    return MonitoringSession.model_construct(**(values | overrides))


def transition(event_type: str, at: datetime) -> MonitoringTimelineEvent:
    return MonitoringTimelineEvent(
        key=f"assessment:{at.isoformat()}", event_type=event_type, occurred_at=at, received_at=at
    )


# -- masking and mapping --------------------------------------------------------------------------------------------


def test_a_plaintext_secret_never_reaches_a_change_set() -> None:
    definition = get_definition("org", "wlans")
    before = protected_configuration({"ssid": "corp", "psk": "hunter2"}, definition)
    after = protected_configuration({"ssid": "corp", "psk": "hunter3"}, definition)

    change = build_change_set(
        [
            ObjectChange(
                logical_object_id=TEMPLATE,
                scope="org",
                object_type="wlans",
                name="corp",
                version=2,
                before=before,
                after=after,
            )
        ]
    )

    rendered = repr(before) + repr(after) + repr(change.masked)
    assert "hunter2" not in rendered
    assert "hunter3" not in rendered
    # The masked marker still compares, so a rotated secret is still a change rather than silently identical.
    assert [atom.attribute for atom in change.atoms] == ["psk"]


def test_a_value_already_protected_is_left_exactly_as_stored() -> None:
    stored = {"psk": {"$encrypted": "ciphertext", "$fingerprint": "fingerprint"}}

    assert protected_configuration(stored, get_definition("org", "wlans")) == stored


def test_masking_reaches_a_sensitive_field_nested_under_a_list() -> None:
    masked = mask_secrets({"radius": [{"secret": "s3cret"}]}, frozenset({"secret"}))

    assert "s3cret" not in repr(masked)


def test_a_device_event_receipt_needs_a_mac_and_a_site() -> None:
    base = {
        "_id": PydanticObjectId(),
        "created_at": NOW,
        "audit_id": AUDIT,
        "deployment": {"event_type": "SW_CONFIGURED", "device_mac": MAC, "site_id": SITE, "occurred_at": NOW},
    }

    assert device_receipt(base) is not None
    assert device_receipt({**base, "deployment": {**base["deployment"], "device_mac": None}}) is None
    assert device_receipt({**base, "deployment": {**base["deployment"], "site_id": None}}) is None
    assert device_receipt({**base, "deployment": None}) is None


def test_an_access_point_revert_is_named_as_unobservable_rather_than_assumed_away() -> None:
    # The legacy normalizer classifies no AP_CONFIG_REVERTED, so no stored receipt can ever carry one, while
    # Guardian's own pairing does recognize the event type. The mapping states that gap instead of hiding it.
    assert outcome_kind("AP_CONFIG_REVERTED") == "reverted"
    assert normalize_deployment("device-events", {"type": "AP_CONFIG_REVERTED", "mac": MAC}) is None
    assert "AP_CONFIG_REVERTED" in service.UNOBSERVABLE_EVENT_TYPES


def test_a_free_form_finding_severity_maps_onto_a_band() -> None:
    observation = DeviceStateObservation(captured_at=NOW)
    record = monitoring_record(
        session(
            incidents=[
                MonitoringIncident(event_type="SW_DISCONNECTED", occurred_at=NOW, severity=ImpactSeverity.CRITICAL)
            ],
            device_comparisons=[
                DeviceStateComparison(
                    triggered_at=NOW,
                    baseline=observation,
                    due_at=NOW,
                    followup=observation,
                    findings=[
                        DeviceStateFinding(
                            kind="port_down",
                            subject="ge-0/0/1",
                            severity="CRITICAL",
                            before="up",
                            after="down",
                            detail="",
                        ),
                        DeviceStateFinding(
                            kind="odd", subject="x", severity="catastrophic", before="", after="", detail=""
                        ),
                    ],
                )
            ],
        )
    )

    assert record is not None
    assert record.incidents[0].severity == "critical"
    assert [finding.severity for finding in record.comparisons[0].findings] == ["critical", "warning"]


def test_a_session_without_a_device_identity_is_not_replayed() -> None:
    assert monitoring_record(session(device_mac="")) is None
    assert monitoring_record(session(site_id="")) is None


def test_a_recorded_observation_keeps_its_metric_states() -> None:
    record = monitoring_record(
        session(
            baseline=SleObservation(captured_at=NOW, values={"wan": 0.9}, metric_states={"wan": "measured"}),
            observations=[SleObservation(captured_at=NOW, values={"wan": 0.4}, metric_states={"wan": "measured"})],
        )
    )

    assert record is not None
    assert record.baseline is not None
    assert record.baseline.metric_states == {"wan": "measured"}
    assert record.observations[0].values == {"wan": 0.4}


# -- triggers -------------------------------------------------------------------------------------------------------


def test_nothing_is_due_before_the_final_minimum_without_a_degradation() -> None:
    assert due_kind(root(), NOW + timedelta(minutes=30), []) is None


def test_an_early_run_is_due_on_a_degradation_transition_before_the_cutoff() -> None:
    sessions = [session(timeline=[transition("ASSESSMENT_WARNING", NOW + timedelta(minutes=5))])]

    assert due_kind(root(), NOW + timedelta(minutes=10), sessions) == "early"


def test_a_transition_before_the_change_is_not_this_audits_degradation() -> None:
    sessions = [session(timeline=[transition("ASSESSMENT_CRITICAL", NOW - timedelta(minutes=1))])]

    assert due_kind(root(), NOW + timedelta(minutes=10), sessions) is None
    assert degraded(sessions, NOW) is False


def test_no_early_run_is_due_after_the_cutoff_and_the_final_takes_over() -> None:
    sessions = [session(timeline=[transition("ASSESSMENT_WARNING", NOW + timedelta(minutes=5))])]

    assert due_kind(root(), NOW + EARLY_CUTOFF, sessions) is None
    assert due_kind(root(), NOW + FINAL_MINIMUM, sessions) == "final"


def test_the_final_wins_when_both_are_due() -> None:
    # The two windows are disjoint by construction (+45 against +60), which is how a late degradation merges into
    # the final rather than racing it. The ordering is asserted over the whole span, so a later limit change that
    # made them overlap would have to keep preferring the final.
    sessions = [session(timeline=[transition("ASSESSMENT_WARNING", NOW)])]
    kinds = {due_kind(root(), NOW + timedelta(minutes=minute), sessions) for minute in range(0, 180, 5)}

    assert kinds == {None, "early", "final"}
    for minute in range(0, 180, 5):
        at = NOW + timedelta(minutes=minute)
        if at >= NOW + FINAL_MINIMUM:
            assert due_kind(root(), at, sessions) == "final"


def test_an_active_linked_session_holds_the_final_until_the_forced_threshold() -> None:
    sessions = [session(active=True)]

    assert due_kind(root(), NOW + FINAL_MINIMUM, sessions) is None
    assert due_kind(root(), NOW + FINAL_FORCED - timedelta(minutes=1), sessions) is None
    assert due_kind(root(), NOW + FINAL_FORCED, sessions) == "final"


def test_exhausted_early_attempts_never_block_the_final() -> None:
    exhausted = root(attempts=SimpleNamespace(early=2, final=0, of=lambda kind: 2 if kind == "early" else 0))
    sessions = [session(timeline=[transition("ASSESSMENT_WARNING", NOW)])]

    assert due_kind(exhausted, NOW + timedelta(minutes=10), sessions) is None
    assert due_kind(exhausted, NOW + FINAL_MINIMUM, sessions) == "final"


def test_a_published_early_run_stops_further_early_runs() -> None:
    published = root(early_run_id=PydanticObjectId())
    sessions = [session(timeline=[transition("ASSESSMENT_WARNING", NOW)])]

    assert due_kind(published, NOW + timedelta(minutes=10), sessions) is None


def test_exhausted_final_attempts_are_never_due_again() -> None:
    exhausted = root(attempts=SimpleNamespace(early=0, final=2, of=lambda kind: 2 if kind == "final" else 0))

    assert due_kind(exhausted, NOW + FINAL_FORCED, []) is None


# -- one attempt ----------------------------------------------------------------------------------------------------


class FakeRuleTransport:
    def __init__(self, result: Any = None, *, failure: str | None = None) -> None:
        self.result = result if result is not None else {"results": [], "total": 0}
        self.failure = failure
        self.calls: list[str] = []

    async def fetch(self, path: str, _params: Any, *, timeout: float, max_bytes: int) -> Any:
        self.calls.append(path)
        if self.failure is not None:
            raise TransportError(self.failure)
        return self.result


class FakeMcpTransport:
    def __init__(self) -> None:
        self.listed = 0

    async def list_tools(self, *, timeout: float, max_bytes: int) -> dict[str, Any]:
        self.listed += 1
        return {"tools": []}

    async def call_tool(self, _name: str, _arguments: Any, *, timeout: float, max_bytes: int) -> dict[str, Any]:
        msg = "no tool is offered"
        raise TransportError(msg)


class FakeModel:
    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.prompts: list[tuple[str, str]] = []

    async def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if not self.replies:
            msg = "the provider is unavailable"
            raise ModelError(msg)
        return self.replies.pop(0)


def inputs(**overrides: Any) -> AttemptInputs:
    values: dict[str, Any] = {
        "organization_id": ORG,
        "audit_id": AUDIT,
        "received_at": NOW,
        "audit_time": NOW,
        "changes": (
            ObjectChange(
                logical_object_id=TEMPLATE,
                scope="org",
                object_type="networktemplates",
                name="DNT-NTR",
                version=7,
                before={"dns_servers": ["10.0.0.1"]},
                after={"dns_servers": ["10.0.0.2"]},
            ),
        ),
        "receipts": (
            DeviceEventReceipt(
                receipt_id="r1",
                received_at=NOW,
                event_type="SW_CONFIG_CHANGED_BY_USER",
                device_mac=MAC,
                site_id=SITE,
                occurred_at=NOW,
                audit_id=AUDIT,
            ),
            DeviceEventReceipt(
                receipt_id="r2",
                received_at=NOW + timedelta(seconds=5),
                event_type="SW_CONFIGURED",
                device_mac=MAC,
                site_id=SITE,
                occurred_at=NOW + timedelta(seconds=5),
                audit_id=AUDIT,
            ),
        ),
        "sessions": (),
    }
    values |= overrides
    monitoring = values.pop("session_records", None)
    if monitoring is not None:
        values["sessions"] = monitoring
    return AttemptInputs(**values)


AP_MAC = "5c5b350a0b02"


def removal() -> dict[str, Any]:
    """A removed site WLAN with an access-point cohort: the change a rule plug-in reads Mist for."""
    return {
        "changes": (
            ObjectChange(
                logical_object_id="00000000000000000000c002",
                scope="site",
                object_type="wlans",
                name="guest",
                version=3,
                before={"ssid": "guest", "enabled": True},
                after={},
                site_id=SITE,
                mist_id="30000000-0000-4000-8000-000000000001",
            ),
        ),
        "receipts": (
            DeviceEventReceipt(
                receipt_id="r1",
                received_at=NOW,
                event_type="AP_CONFIG_CHANGED_BY_USER",
                device_mac=AP_MAC,
                site_id=SITE,
                occurred_at=NOW,
                audit_id=AUDIT,
            ),
        ),
    }


async def run_attempt(**overrides: Any) -> Any:
    tools = overrides.pop("tools", AttemptTools(rule_transport=FakeRuleTransport(), skip_reason=NO_RUNTIME))
    started = overrides.pop("started", time.monotonic())
    clock = overrides.pop("clock", time.monotonic)
    return await execute_attempt(
        inputs(**overrides), tools=tools, started=started, as_of=NOW + timedelta(minutes=30), clock=clock
    )


async def test_an_attempt_publishes_a_deterministic_verdict_with_no_agent() -> None:
    outcome = await run_attempt()

    assert outcome.state == "succeeded"
    verdict = outcome.fields["verdict"]
    assert isinstance(verdict, Verdict)
    assert outcome.fields["agent"].concluded is False
    assert outcome.fields["agent"].reason == NO_RUNTIME
    assert outcome.fields["anchor"].source == "audit"
    assert outcome.fields["as_of"] == NOW + timedelta(minutes=30)
    assert [atom.attribute for atom in outcome.fields["change"]] == ["dns_servers"]
    assert outcome.fields["ledger"]


async def test_a_receipt_anchor_can_never_publish_none() -> None:
    outcome = await run_attempt(audit_time=None, receipts=())

    assert outcome.fields["anchor"].source == "receipt"
    assert outcome.fields["verdict"].coverage != "complete"
    assert outcome.fields["verdict"].current != "none"


async def test_an_earliest_device_trigger_anchors_a_run_whose_audit_carries_no_time() -> None:
    outcome = await run_attempt(audit_time=None)

    assert outcome.fields["anchor"].source == "device_trigger"
    assert outcome.fields["anchor"].changed_at == NOW


async def test_a_change_set_that_cannot_be_built_fails_the_attempt() -> None:
    duplicated = inputs().changes[0]
    outcome = await run_attempt(changes=(duplicated, duplicated))

    assert outcome.state == "failed"
    assert outcome.failure_reason is not None
    assert "\n" not in outcome.failure_reason


async def test_a_rule_plug_in_reads_through_the_reader_alone() -> None:
    transport = FakeRuleTransport({"results": [], "total": 0})
    outcome = await run_attempt(tools=AttemptTools(rule_transport=transport, skip_reason=NO_RUNTIME), **removal())

    assert transport.calls
    assert outcome.state == "succeeded"
    assert any(item.source.startswith("rule:") for item in outcome.fields["evidence"])


async def test_a_failed_rule_read_is_a_gap_and_never_a_failed_attempt() -> None:
    tools = AttemptTools(rule_transport=FakeRuleTransport(failure="Mist is unavailable"), skip_reason=NO_RUNTIME)
    outcome = await run_attempt(tools=tools, **removal())

    assert outcome.state == "succeeded"
    assert any(item.collection == "error" for item in outcome.fields["evidence"])
    assert outcome.fields["verdict"].gaps


async def test_no_external_call_starts_after_its_phase_deadline() -> None:
    transport = FakeRuleTransport()
    tools = AttemptTools(rule_transport=transport, skip_reason=NO_RUNTIME)
    # A commit whose response was slow leaves the rule phase already over when execution starts.
    outcome = await run_attempt(tools=tools, started=time.monotonic() - RULE_PHASE.total_seconds() - 1, **removal())

    assert outcome.state == "succeeded"
    assert transport.calls == []


async def test_the_agent_is_skipped_with_the_reason_its_availability_gives() -> None:
    for reason in (NO_RUNTIME, NO_MCP_ENDPOINT, NO_CAPABILITY):
        outcome = await run_attempt(tools=AttemptTools(rule_transport=FakeRuleTransport(), skip_reason=reason))

        assert outcome.fields["agent"].reason == reason
        assert outcome.state == "succeeded"


async def test_a_provider_failure_still_composes_a_deterministic_verdict() -> None:
    tools = AttemptTools(rule_transport=FakeRuleTransport(), mcp_transport=FakeMcpTransport(), model_client=FakeModel())
    outcome = await run_attempt(tools=tools)

    assert outcome.state == "succeeded"
    assert outcome.fields["agent"].concluded is False
    assert "provider" in (outcome.fields["agent"].reason or "")
    assert outcome.fields["verdict"].confidence == "low"


async def test_the_agent_phase_is_over_before_its_first_turn_when_the_commit_was_slow() -> None:
    model = FakeModel('{"action": "report"}')
    tools = AttemptTools(rule_transport=FakeRuleTransport(), mcp_transport=FakeMcpTransport(), model_client=model)
    outcome = await run_attempt(tools=tools, started=time.monotonic() - AGENT_PHASE.total_seconds() - 1)

    assert model.prompts == []
    assert outcome.fields["agent"].concluded is False
    assert outcome.fields["budget"].model_turns == 0


async def test_an_attempt_records_the_budget_every_source_spent() -> None:
    tools = AttemptTools(
        rule_transport=FakeRuleTransport(), mcp_transport=FakeMcpTransport(), model_client=FakeModel("not json")
    )
    outcome = await run_attempt(tools=tools)

    budget = outcome.fields["budget"]
    assert budget.model_turns >= 1
    assert budget.mcp_calls == 0


async def test_every_stored_list_is_bounded_by_its_own_budget() -> None:
    record = monitoring_record(
        session(
            timeline=[transition("ASSESSMENT_WARNING", NOW)],
            baseline=SleObservation(captured_at=NOW, values={"wan": 0.99}, metric_states={"wan": "measured"}),
            observations=[SleObservation(captured_at=NOW, values={"wan": 0.10}, metric_states={"wan": "measured"})],
        )
    )
    outcome = await run_attempt(sessions=(record,))

    assert json_size(outcome.fields["change"]) <= CHANGE_VIEW_BUDGET
    assert json_size(outcome.fields["ledger"]) <= LEDGER_VIEW_BUDGET
    assert json_size(outcome.fields["obligations"]) <= LEDGER_VIEW_BUDGET
    assert json_size(outcome.fields["steps"]) <= STEPS_BUDGET
    assert json_size(outcome.fields["monitoring"]) <= CONCLUSIONS_BUDGET
    assert json_size(outcome.fields["deployment"]) <= CONCLUSIONS_BUDGET


async def test_every_stored_run_field_is_one_the_finalization_builder_accepts() -> None:
    outcome = await run_attempt()

    assert set(outcome.fields) <= RUN_OUTCOME_FIELDS


# -- publication text -----------------------------------------------------------------------------------------------


def verdict(**overrides: Any) -> Verdict:
    values: dict[str, Any] = {
        "peak": "warning",
        "current": "none",
        "recovery": "recovered",
        "confidence": "low",
        "coverage": "partial",
        "summary": "One switch degraded and recovered.",
    }
    return Verdict(**(values | overrides))


def test_a_final_status_reason_stays_within_the_stored_bound() -> None:
    reason = _status_reason(verdict(summary="x " * 999, current="warning", recovery="unrecovered"))

    assert 1 <= len(reason) <= 400
    assert "\n" not in reason


def test_a_verdict_without_a_summary_still_completes_the_root() -> None:
    assert "no summary" in _status_reason(verdict(summary="", current="warning", recovery="unrecovered"))


# -- root creation --------------------------------------------------------------------------------------------------


class RecordingCollection:
    def __init__(self) -> None:
        self.updates: list[tuple[dict[str, Any], Any, bool]] = []

    async def update_one(self, criteria: dict[str, Any], update: Any, *, upsert: bool = False) -> Any:
        self.updates.append((criteria, update, upsert))
        return SimpleNamespace(modified_count=1, matched_count=1, upserted_id=PydanticObjectId())


async def test_ensure_pins_retention_and_the_initial_scheduling_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = RecordingCollection()
    monkeypatch.setattr(GuardianInvestigation, "get_pymongo_collection", classmethod(lambda _cls: collection))
    organization = Organization.model_construct(id=ORG, mist_org_id="org-1", monitoring_retention_days=30)
    changed_at = datetime.now(UTC) + timedelta(minutes=5)

    await GuardianService(vault()).ensure(organization, AUDIT, changed_at=changed_at, anchor_known=True)

    criteria, update, upsert = collection.updates[0]
    inserted = update["$setOnInsert"]
    assert (criteria, upsert) == ({"organization_id": ORG, "audit_id": AUDIT}, True)
    # The hint is max(worker now, changed_at) + 1 min; a future audit time is never checked before it happened.
    assert inserted["next_check_at"] == changed_at + RECHECK_DELAY
    assert inserted["retained_until"] - inserted["created_at"] == timedelta(days=30)
    assert inserted["claim"] is None


async def test_an_organization_without_a_usable_policy_retains_for_one_day(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = RecordingCollection()
    monkeypatch.setattr(GuardianInvestigation, "get_pymongo_collection", classmethod(lambda _cls: collection))
    organization = Organization.model_construct(id=ORG, mist_org_id="org-1", monitoring_retention_days=0)

    await GuardianService(vault()).ensure(organization, AUDIT, changed_at=NOW, anchor_known=False)

    inserted = collection.updates[0][1]["$setOnInsert"]
    assert inserted["retained_until"] - inserted["created_at"] == timedelta(days=1)
    assert inserted["anchor_known"] is False


# -- worker gating --------------------------------------------------------------------------------------------------


async def _tick_worker(monkeypatch: pytest.MonkeyPatch, *, guardian_enabled: bool) -> list[str]:
    """Run the monitoring worker tick and report which due-investigation polls it started."""
    polled: list[str] = []

    class FakeDatabase:
        def __init__(self, _settings: object) -> None:
            pass

        async def connect(self) -> None: ...

        async def close(self) -> None: ...

    async def poll_active(_self: object) -> int:
        return 0

    async def guardian_poll(_self: object) -> int:
        polled.append("guardian")
        return 0

    async def legacy_poll(_self: object) -> None:
        polled.append("legacy")

    monkeypatch.setattr(task, "get_settings", lambda: Settings(guardian_enabled=guardian_enabled))
    monkeypatch.setattr(task, "DatabaseManager", FakeDatabase)
    monkeypatch.setattr(MonitoringPollService, "poll_active", poll_active)
    monkeypatch.setattr(GuardianService, "poll_due", guardian_poll)
    monkeypatch.setattr(ImpactInvestigationService, "poll_due", legacy_poll)

    await task._poll_active_monitoring()
    return polled


async def test_the_worker_polls_nothing_new_while_the_feature_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await _tick_worker(monkeypatch, guardian_enabled=False) == []


async def test_the_worker_polls_guardian_once_the_feature_is_on(monkeypatch: pytest.MonkeyPatch) -> None:
    assert await _tick_worker(monkeypatch, guardian_enabled=True) == ["guardian"]


# -- inputs the attempt never saw in full ------------------------------------------------------------------------


def _core_obligations(outcome: Any) -> list[Any]:
    return [item for item in outcome.fields["obligations"] if item.obligation.kind == "input"]


async def test_a_read_cap_that_fired_is_a_core_gap_and_an_unsatisfied_core_obligation() -> None:
    dropped = (
        "This audit changed more than 200 object versions; the changed objects beyond that limit were not examined"
    )
    outcome = await run_attempt(gaps=(dropped,))

    missing = _core_obligations(outcome)
    assert [item.status.status for item in missing] == ["unsatisfied"]
    assert [item.status.reason for item in missing] == [dropped]
    assert Gap(source="core", text=dropped) in outcome.fields["verdict"].gaps
    assert outcome.fields["verdict"].coverage != "complete"


async def test_a_net_change_that_ends_where_it_started_is_reported_rather_than_elided() -> None:
    # Disabled, then re-enabled: two versions inside one audit whose net configuration is identical, so the
    # change set has the object but no atom at all, and nothing else would record that the audit touched it.
    unchanged = ObjectChange(
        logical_object_id="00000000000000000000c003",
        scope="org",
        object_type="networktemplates",
        name="DNT-NTR",
        version=9,
        before={"dns_servers": ["10.0.0.1"]},
        after={"dns_servers": ["10.0.0.1"]},
    )
    superseded = (
        SupersededObject(
            logical_object_id=unchanged.logical_object_id, name="DNT-NTR", versions=2, attributes=("dns_servers",)
        ),
    )
    outcome = await run_attempt(changes=(unchanged,), superseded=superseded)

    missing = _core_obligations(outcome)
    assert len(missing) == 1
    reason = missing[0].status.reason or ""
    assert "DNT-NTR" in reason
    assert "was changed 2 times" in reason
    assert "dns_servers ended where they started" in reason
    assert outcome.fields["verdict"].coverage != "complete"
    assert any(gap.source == "core" and "DNT-NTR" in gap.text for gap in outcome.fields["verdict"].gaps)


async def test_an_attribute_put_back_inside_one_audit_is_reported_even_beside_one_that_changed() -> None:
    # The object changed dns_servers and reverted ntp_servers: the first compiles to an atom, a ledger row and a
    # precondition a plug-in can satisfy, while the second leaves nothing at all behind.
    changed = inputs().changes[0]
    superseded = (
        SupersededObject(
            logical_object_id=changed.logical_object_id,
            name="DNT-NTR",
            versions=2,
            attributes=("dns_servers", "ntp_servers"),
        ),
    )
    outcome = await run_attempt(superseded=superseded)

    missing = _core_obligations(outcome)
    assert len(missing) == 1
    reason = missing[0].status.reason or ""
    assert "ntp_servers ended where they started" in reason
    assert "dns_servers" not in reason
    assert outcome.fields["verdict"].coverage != "complete"


async def test_an_object_with_no_stored_identity_is_reported_by_the_loader() -> None:
    gap = service.UNIDENTIFIED_GAP.format(count=2)
    outcome = await run_attempt(gaps=(gap,))

    assert [item.status.reason for item in _core_obligations(outcome)] == [gap]
    assert outcome.fields["verdict"].coverage != "complete"


async def test_an_object_whose_every_touched_attribute_is_in_its_net_change_is_not_reported() -> None:
    changed = inputs().changes[0]
    superseded = (
        SupersededObject(
            logical_object_id=changed.logical_object_id, name="DNT-NTR", versions=3, attributes=("dns_servers",)
        ),
    )
    outcome = await run_attempt(superseded=superseded)

    assert _core_obligations(outcome) == []


async def test_a_single_version_change_with_no_atom_is_not_reported_as_elided() -> None:
    unchanged = ObjectChange(
        logical_object_id="00000000000000000000c004",
        scope="org",
        object_type="networktemplates",
        name="DNT-NTR",
        version=1,
        before={"dns_servers": ["10.0.0.1"]},
        after={"dns_servers": ["10.0.0.1"]},
    )
    outcome = await run_attempt(changes=(unchanged,))

    assert _core_obligations(outcome) == []


# -- transports ---------------------------------------------------------------------------------------------------


async def test_building_the_attempts_tools_closes_whatever_it_already_opened(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[str] = []

    class Recording(service.MistRuleTransport):
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def aclose(self) -> None:
            closed.append("rule")

    async def unavailable(_self: object) -> None:
        msg = "the provider settings could not be read"
        raise RuntimeError(msg)

    monkeypatch.setattr(service, "MistRuleTransport", Recording)
    monkeypatch.setattr(service, "service_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(service.ApplicationConfigurationService, "ai_runtime", unavailable)
    organization = Organization.model_construct(id=ORG, mist_org_id="org-1", cloud_region=MistCloudRegion.GLOBAL_01)

    with pytest.raises(RuntimeError, match="provider settings"):
        async with service.GuardianTools(organization, vault=vault()):
            pass

    assert closed == ["rule"]


async def test_a_mist_read_is_bounded_while_it_streams() -> None:
    transport = service.MistRuleTransport(token="token", base_url="https://api.example.invalid")
    sent: list[int] = []

    async def stream() -> Any:
        for _chunk in range(10):
            sent.append(1)
            yield b"x" * 64

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=stream())

    transport._client = httpx.AsyncClient(
        base_url="https://api.example.invalid", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(TransportError, match="transport bound"):
            await transport.fetch("/api/v1/self", {}, timeout=1.0, max_bytes=100)
    finally:
        await transport.aclose()

    # The read stopped as soon as the bound was passed rather than buffering the whole body first.
    assert len(sent) < 10


async def test_a_bounded_mist_read_returns_its_parsed_result() -> None:
    transport = service.MistRuleTransport(token="token", base_url="https://api.example.invalid")
    transport._client = httpx.AsyncClient(
        base_url="https://api.example.invalid",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, json={"results": [], "total": 0})),
    )
    try:
        assert await transport.fetch("/api/v1/self", {}, timeout=1.0, max_bytes=1000) == {"results": [], "total": 0}
    finally:
        await transport.aclose()
