"""Guardian monitoring replay: check treatments, session classification, severity components and bounded evidence."""

import random
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from guardian_verification import load_fixture
from mist_config_guardian_backend.guardian.change import ChangedObject, ChangeSet
from mist_config_guardian_backend.guardian.contracts import (
    ChangeAtom,
    ExpectedDevice,
    Obligation,
    ObligationStatus,
    RulePlan,
    RunAnchor,
    Target,
    band_rank,
)
from mist_config_guardian_backend.guardian.deployment import (
    DeploymentReplay,
    DeviceEventReceipt,
    ReplayFrame,
    pair_deployments,
)
from mist_config_guardian_backend.guardian.evidence import MONITORING_EVIDENCE_BUDGET, EvidenceRegistry, json_size
from mist_config_guardian_backend.guardian.ledger import Ledger, build_ledger
from mist_config_guardian_backend.guardian.monitoring import (
    ACTIVE_REASON,
    DISAPPEARED_REASON,
    NO_BASELINE_DATA_REASON,
    NO_DATA_REASON,
    NO_DEVICE_REASON,
    NO_EXPECTED_DEVICES_GAP,
    NO_SESSION_REASON,
    NOT_COMPARABLE_REASON,
    SHARED_SESSION_REASON,
    ComparisonRecord,
    FindingRecord,
    IncidentRecord,
    MonitoringRecord,
    MonitoringReplay,
    SleSample,
    check_status,
    metric_check,
    metric_severity,
    record_monitoring,
    replay_monitoring,
)
from mist_config_guardian_backend.models.monitoring import RelevancePlan, SleObservation
from mist_config_guardian_backend.services.impact_analysis import assess_impact
from mist_config_guardian_backend.services.impact_evidence import evidence_rows

AUDIT = "30000000-0000-4000-8000-000000000001"
OTHER = "30000000-0000-4000-8000-000000000002"
SITE = "20000000-0000-4000-8000-000000000001"
SITE_B = "20000000-0000-4000-8000-000000000002"
X = "020000000021"
Y = "020000000022"
Z = "020000000031"
T0 = datetime(2026, 9, 16, 4, 41, 35, tzinfo=UTC)
CHANGED = T0 + timedelta(milliseconds=242)
AS_OF = T0 + timedelta(hours=2)
METRIC = "ap-health"
FAILED_STATES = ("error", "missing", "pending", "unsupported", "disabled")


def minutes(value: float) -> datetime:
    return T0 + timedelta(minutes=value)


def frame(as_of: datetime = AS_OF) -> ReplayFrame:
    return ReplayFrame(audit_id=AUDIT, anchor=RunAnchor(changed_at=CHANGED, source="audit"), as_of=as_of)


def sle(
    at: float, metrics: dict[str, float | str], *, scope_id: str | None = X, errors: tuple[str, ...] = ()
) -> SleSample:
    """An observation ``at`` minutes after T0: a number is measured, a state name records that state."""
    values: dict[str, float] = {}
    no_data: list[str] = []
    metric_errors: dict[str, str] = {}
    metric_states: dict[str, str] = {}
    for name, value in metrics.items():
        if isinstance(value, (int, float)):
            values[name] = float(value)
        elif value == "no_data":
            no_data.append(name)
        elif value == "error":
            metric_errors[name] = f"{name}: HTTP 500 from the SLE endpoint"
        elif value in {"unsupported", "disabled"}:
            metric_states[name] = value
    return SleSample.model_validate(
        {
            "captured_at": minutes(at),
            "scope": "device",
            "scope_id": scope_id,
            "values": values,
            "no_data": no_data,
            "errors": errors,
            "requested_metrics": list(metrics),
            "metric_errors": metric_errors,
            "metric_states": metric_states,
        }
    )


def state_sample(at: float, state: str, value: float = 100) -> SleSample | None:
    return None if state == "pending" else sle(at, {METRIC: value if state == "measured" else state})


BASELINE = sle(-1, {METRIC: 100})


def session(  # noqa: PLR0913 - one argument per recorded field a case varies
    mac: str = X,
    *,
    audits: tuple[str, ...] = (AUDIT,),
    active: bool = False,
    completed: float | None = 60,
    baseline: SleSample | None = BASELINE,
    observations: tuple[SleSample, ...] = (),
    incidents: tuple[IncidentRecord, ...] = (),
    comparisons: tuple[ComparisonRecord, ...] = (),
    created: float = 0.1,
    site: str = SITE,
    session_id: str = "",
) -> MonitoringRecord:
    return MonitoringRecord(
        session_id=session_id or f"session-{mac}-{created}",
        device_mac=mac,
        site_id=site,
        device_name=f"AP {mac[-2:]}",
        audit_ids=audits,
        created_at=minutes(created),
        active=active,
        completed_at=None if completed is None else minutes(completed),
        baseline=baseline,
        observations=observations,
        incidents=incidents,
        comparisons=comparisons,
    )


def obligation(  # noqa: PLR0913 - one argument per obligation field a case varies
    target: Target | str = X,
    *,
    metric: str = METRIC,
    policy: str = "incomplete",
    owner: str = "dns",
    local: str = "O1",
    kind: str = "monitoring",
) -> Obligation:
    resolved = Target(device_mac=target, site_id=SITE) if isinstance(target, str) else target
    fields = {"metric": metric, "empty_policy": policy} if kind == "monitoring" else {}
    return Obligation.model_validate(
        {
            "id": local,
            "owner": owner,
            "change_ref": "A1",
            "paths": [["dns_servers"]],
            "role": "observation",
            "kind": kind,
            "target": resolved,
            **fields,
        }
    )


def setup(
    *obligations: Obligation,
    devices: tuple[tuple[str, str], ...] = ((X, SITE),),
    selections: dict[str, dict[str, tuple[str, ...]]] | None = None,
) -> tuple[Ledger, dict[str, RulePlan]]:
    template = ChangedObject(logical_object_id="template", scope="org", object_type="networktemplates", version=1)
    atom = ChangeAtom(
        id="A1",
        logical_object_id="template",
        version=1,
        attribute="dns_servers",
        paths=(("dns_servers",),),
        paths_complete=True,
    )
    plans = {
        owner: RulePlan(
            obligations=tuple(o for o in obligations if o.owner == owner),
            **(selections or {}).get(owner, {}),
        )
        for owner in sorted({o.owner for o in obligations})
    }
    ledger = build_ledger(
        ChangeSet(objects=(template,), atoms=(atom,)),
        [ExpectedDevice(mac=mac, site_id=site) for mac, site in devices],
        plans,
        "audit",
    )
    return ledger, plans


def replay(  # noqa: PLR0913 - the replay's inputs
    sessions: list[MonitoringRecord],
    *obligations: Obligation,
    devices: tuple[tuple[str, str], ...] = ((X, SITE),),
    selections: dict[str, dict[str, tuple[str, ...]]] | None = None,
    as_of: datetime = AS_OF,
    expected: tuple[ExpectedDevice, ...] | None = None,
    deployment: DeploymentReplay | None = None,
) -> tuple[Ledger, MonitoringReplay]:
    ledger, plans = setup(*(obligations or (obligation(),)), devices=devices, selections=selections)
    result = replay_monitoring(
        sessions,
        frame=frame(as_of),
        ledger=ledger,
        plans=plans,
        expected=tuple(ExpectedDevice(mac=mac, site_id=site) for mac, site in devices)
        if expected is None
        else expected,
        deployment=deployment or DeploymentReplay(),
    )
    return ledger, result


def status_of(ledger: Ledger, result: MonitoringReplay, metric: str = METRIC) -> ObligationStatus:
    [found] = [result.statuses[o.id] for o in ledger.obligations if o.kind == "monitoring" and o.metric == metric]
    return found


# Parity with monitoring's own assessment ---------------------------------------------------------------------------

POOL = ("ap-health", "coverage", "roaming")
VALUES = (100.0, 95.0, 90.01, 90.0, 89.99, 75.01, 75.0, 74.99, 60.0, 0.0, 110.0)
STATES = ("measured", "no_data", "pending", "missing", "error", "unsupported", "disabled")


def random_observation(rng: random.Random, at: datetime) -> dict[str, object]:
    """Recorded SLE fields the way collectors and legacy documents may leave them."""
    values: dict[str, float] = {}
    no_data: list[str] = []
    errors: list[str] = []
    metric_errors: dict[str, str] = {}
    metric_states: dict[str, str] = {}
    requested: list[str] = []
    for name in POOL:
        shape = rng.choice(("measured", "measured", "no_data", "error", "legacy_error", "state", "stale", "absent"))
        if shape != "absent" and rng.random() < 0.7:
            requested.append(name)
        if shape == "measured":
            values[name] = rng.choice(VALUES)
        elif shape == "no_data":
            no_data.append(name)
        elif shape == "error":
            metric_errors[name] = f"{name}: HTTP 500"
        elif shape == "legacy_error":
            errors.append(f"{name}: unavailable")
        elif shape == "state":
            metric_states[name] = rng.choice(STATES)
            if rng.random() < 0.5:
                values[name] = rng.choice(VALUES)
        elif shape == "stale":
            metric_states[name] = "measured"
    errors += rng.choice(([], [], ["metric discovery: unavailable"], ["general failure"], ["other-metric: HTTP 404"]))
    return {
        "captured_at": at,
        "scope": rng.choice(("device", "device", "device", "site")),
        "scope_id": rng.choice((X, X, X, Y, None)),
        "values": values,
        "no_data": no_data,
        "errors": errors,
        "requested_metrics": requested,
        "metric_errors": metric_errors,
        "metric_states": metric_states,
    }


def parity_cases(count: int = 4_000):
    rng = random.Random(20260916)  # noqa: S311 - reproducible generated cases, not a secret
    for _ in range(count):
        baseline = None if rng.random() < 0.08 else random_observation(rng, T0)
        latest = None if rng.random() < 0.08 else random_observation(rng, minutes(10))
        selected = tuple(sorted(rng.sample(POOL, rng.randint(0, len(POOL)))))
        yield baseline, latest, selected


def both(recorded: dict[str, object] | None) -> tuple[SleObservation | None, SleSample | None]:
    if recorded is None:
        return None, None
    return SleObservation.model_validate(recorded), SleSample.model_validate(recorded)


def test_metric_severity_matches_monitorings_assessment_of_the_selected_metrics():
    for baseline, latest, selected in parity_cases():
        old_baseline, new_baseline = both(baseline)
        old_latest, new_latest = both(latest)
        expected = assess_impact(
            old_baseline, old_latest, [], relevance_plan=RelevancePlan(mode="selected", metrics=list(selected))
        ).severity.value
        assert metric_severity(new_baseline, new_latest, selected) == expected, (baseline, latest, selected)


def test_metric_checks_match_monitorings_recorded_evidence_rows():
    for baseline, latest, _ in parity_cases():
        old_baseline, new_baseline = both(baseline)
        old_latest, new_latest = both(latest)
        rows = {row.name: row for row in evidence_rows(old_baseline, old_latest, RelevancePlan(metrics=list(POOL)))}
        for name in POOL:
            check = metric_check(new_baseline, new_latest, name)
            row = rows[name]
            assert (check.before, check.after) == (row.baseline_state, row.latest_state)
            assert (check.value_before, check.value_after) == (row.baseline, row.latest)
            assert (check.delta, check.comparable) == (row.delta, row.comparable)


@pytest.mark.parametrize(
    ("baseline", "latest", "selected", "expected"),
    [
        pytest.param({METRIC: 100}, {METRIC: 100}, (METRIC,), "none", id="unchanged"),
        pytest.param({METRIC: 100}, {METRIC: 90.01}, (METRIC,), "none", id="just above the warning delta"),
        pytest.param({METRIC: 100}, {METRIC: 90}, (METRIC,), "warning", id="warning delta"),
        pytest.param({METRIC: 100}, {METRIC: 75.01}, (METRIC,), "warning", id="just above the critical delta"),
        pytest.param({METRIC: 100}, {METRIC: 75}, (METRIC,), "critical", id="critical delta"),
        pytest.param({METRIC: 100}, {METRIC: "no_data"}, (METRIC,), "info", id="no delta"),
        pytest.param({METRIC: 100, "coverage": "error"}, {METRIC: 99}, (METRIC, "coverage"), "info", id="partial"),
        pytest.param({METRIC: 100, "coverage": "error"}, {METRIC: 50}, (METRIC, "coverage"), "critical", id="drop"),
        pytest.param({METRIC: 100, "coverage": "error"}, {METRIC: 99}, (METRIC,), "none", id="unselected error"),
        pytest.param({METRIC: 100}, {METRIC: 40}, (), "info", id="nothing selected"),
    ],
)
def test_metric_severity_thresholds(baseline, latest, selected, expected):
    assert metric_severity(sle(0, baseline), sle(10, latest), selected) == expected


def test_metric_severity_needs_one_scope():
    assert metric_severity(sle(0, {METRIC: 100}), sle(10, {METRIC: 10}, scope_id=Y), (METRIC,)) == "info"


# The required-check treatment table --------------------------------------------------------------------------------

TREATMENTS = [
    ("measured", "measured", "incomplete", "satisfied", None),
    ("measured", "measured", "not_exercised", "satisfied", None),
    ("no_data", "no_data", "not_exercised", "not_exercised", None),
    ("no_data", "no_data", "incomplete", "unsatisfied", NO_DATA_REASON),
    ("measured", "no_data", "not_exercised", "unsatisfied", DISAPPEARED_REASON),
    ("measured", "no_data", "incomplete", "unsatisfied", DISAPPEARED_REASON),
    ("no_data", "measured", "not_exercised", "unsatisfied", NO_BASELINE_DATA_REASON),
    ("no_data", "measured", "incomplete", "unsatisfied", NO_BASELINE_DATA_REASON),
    *(
        (state, other, policy, "unsatisfied", f"The baseline is {state}")
        for state in FAILED_STATES
        for other in (*STATES,)
        for policy in ("not_exercised", "incomplete")
    ),
    *(
        (other, state, policy, "unsatisfied", f"The latest observation is {state}")
        for state in FAILED_STATES
        for other in ("measured", "no_data")
        for policy in ("not_exercised", "incomplete")
    ),
]


@pytest.mark.parametrize(("before", "after", "policy", "status", "reason"), TREATMENTS)
def test_the_required_check_treatment_table(before, after, policy, status, reason):
    check = metric_check(state_sample(-1, before), state_sample(10, after, 90), METRIC)

    assert (check.before, check.after) == (before, after)
    assert check_status(check, policy) == ObligationStatus(status=status, reason=reason)


def test_measured_values_on_different_scopes_are_not_a_comparison():
    check = metric_check(sle(-1, {METRIC: 100}), sle(10, {METRIC: 100}, scope_id=Y), METRIC)
    assert check_status(check, "incomplete") == ObligationStatus(status="unsatisfied", reason=NOT_COMPARABLE_REASON)


def test_a_not_exercised_check_stays_listed_with_its_zero_sample_evidence():
    baseline = sle(-1, {METRIC: "no_data"})
    _, result = replay(
        [session(baseline=baseline, observations=(sle(10, {METRIC: "no_data"}),))],
        obligation(policy="not_exercised"),
    )
    [device] = result.devices
    [check] = device.checks
    assert (check.metric, check.before, check.after, check.treatment) == (METRIC, "no_data", "no_data", "not_exercised")


def test_treatments_use_the_devices_latest_observation_through_as_of():
    observations = (sle(10, {METRIC: 100}), sle(20, {METRIC: "no_data"}), sle(130, {METRIC: 100}))
    ledger, result = replay([session(observations=observations, completed=130)], as_of=minutes(125))
    [device] = result.devices
    [check] = device.checks
    assert (check.after, check.treatment) == ("no_data", "unsatisfied")
    assert status_of(ledger, result).reason == ACTIVE_REASON


# Session classification --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "exclusive", "terminal", "reason"),
    [
        pytest.param(session(observations=(sle(10, {METRIC: 99}),)), True, True, None, id="exclusive terminal"),
        pytest.param(
            session(audits=(AUDIT, OTHER), observations=(sle(10, {METRIC: 99}),)),
            False,
            True,
            SHARED_SESSION_REASON,
            id="shared",
        ),
        pytest.param(
            session(audits=(OTHER, AUDIT), active=True, completed=None), False, False, SHARED_SESSION_REASON, id="both"
        ),
        pytest.param(
            session(active=True, completed=None, observations=(sle(10, {METRIC: 99}),)),
            True,
            False,
            ACTIVE_REASON,
            id="active",
        ),
        pytest.param(
            session(completed=121, observations=(sle(10, {METRIC: 99}),)),
            True,
            False,
            ACTIVE_REASON,
            id="completed after as_of",
        ),
    ],
)
def test_sessions_are_classified_exclusive_and_terminal(record, exclusive, terminal, reason):
    snapshot = record.model_copy(deep=True)
    ledger, result = replay([record])
    [device] = result.devices

    assert (device.exclusive, device.terminal) == (exclusive, terminal)
    assert status_of(ledger, result) == (
        ObligationStatus(status="satisfied")
        if reason is None
        else ObligationStatus(status="unsatisfied", reason=reason)
    )
    assert record == snapshot


@pytest.mark.parametrize(
    "sessions",
    [
        pytest.param([], id="no session"),
        pytest.param([session(audits=(OTHER,))], id="another audit's session"),
        pytest.param([session(Y)], id="another device's session"),
        pytest.param([session(created=121)], id="a session created after as_of"),
    ],
)
def test_a_device_without_a_linked_session_is_unsatisfied(sessions):
    ledger, result = replay(sessions)
    [device] = result.devices
    assert (device.session_id, device.exclusive, device.terminal, device.peak) == (None, None, None, None)
    assert status_of(ledger, result) == ObligationStatus(status="unsatisfied", reason=NO_SESSION_REASON)


def test_the_latest_of_several_linked_sessions_is_used_with_a_gap():
    older = session(created=0.1, session_id="older", observations=(sle(10, {METRIC: 10}),))
    newer = session(created=30, session_id="newer", observations=(sle(40, {METRIC: 99}),))
    _, result = replay([newer, older])
    [device] = result.devices
    assert device.session_id == "newer"
    assert any("Several monitoring sessions" in gap and X in gap for gap in result.gaps)


def test_no_expected_devices_adds_the_exact_gap():
    _, result = replay([session(observations=(sle(10, {METRIC: 99}),))], expected=())
    assert NO_EXPECTED_DEVICES_GAP == "No audit-linked device deployment events were observed."
    assert NO_EXPECTED_DEVICES_GAP in result.gaps


def test_a_shared_session_is_evidence_and_a_gap_never_a_severity_floor():
    shared = session(
        audits=(AUDIT, OTHER),
        observations=(sle(10, {METRIC: 5}),),
        incidents=(IncidentRecord(event_type="AP_DISCONNECTED", occurred_at=minutes(5), severity="critical"),),
        comparisons=(
            ComparisonRecord(
                followup_at=minutes(6),
                findings=(FindingRecord(kind="device_disconnected", severity="critical"),),
                latest_at=minutes(50),
                current_findings=(FindingRecord(kind="device_disconnected", severity="critical"),),
            ),
        ),
    )
    ledger, result = replay(
        [shared],
        selections={"dns": {"incident_types": ("AP_DISCONNECTED",), "finding_kinds": ("device_disconnected",)}},
    )
    [device] = result.devices

    assert device.exclusive is False
    assert (device.peak, device.current, device.metrics, device.incidents, device.device_state) == (None,) * 5
    assert (result.peak, result.current) == ("none", "none")
    assert status_of(ledger, result).reason == SHARED_SESSION_REASON
    assert any("shared with other audits" in gap and X in gap for gap in result.gaps)
    [check] = device.checks
    assert (check.value_before, check.value_after, check.delta) == (100, 5, -95)

    registry = EvidenceRegistry()
    conclusion = record_monitoring(result, frame=frame(), registry=registry)
    assert conclusion.impacted_devices == ()
    assert (conclusion.peak, conclusion.current) == ("none", "none")
    [item] = registry.evidence
    assert item.payload["exclusive"] is False


def test_an_active_exclusive_session_still_sets_its_severity_for_early_runs():
    ledger, result = replay([session(active=True, completed=None, observations=(sle(10, {METRIC: 50}),))])
    assert status_of(ledger, result).reason == ACTIVE_REASON
    assert (result.peak, result.current) == ("critical", "critical")


# Severity components -----------------------------------------------------------------------------------------------

INCIDENT_SELECTION = {"dns": {"incident_types": ("AP_DISCONNECTED",)}}
FINDING_SELECTION = {"dns": {"finding_kinds": ("port_down",)}}


def device_of(result: MonitoringReplay):
    [device] = result.devices
    return device


def test_metric_peak_is_the_worst_observation_and_current_the_final_one():
    observations = (sle(10, {METRIC: 99}), sle(20, {METRIC: 60}), sle(30, {METRIC: 88}), sle(40, {METRIC: 100}))
    device = device_of(replay([session(observations=observations)])[1])
    assert device.metrics is not None
    assert (device.metrics.peak, device.metrics.current) == ("critical", "none")
    assert (device.peak, device.current) == ("critical", "none")


def test_observations_after_as_of_are_not_replayed():
    observations = (sle(10, {METRIC: 99}), sle(20, {METRIC: 100}), sle(30, {METRIC: 10}))
    device = device_of(replay([session(observations=observations, completed=30)], as_of=minutes(25))[1])
    assert device.metrics is not None
    assert (device.metrics.peak, device.metrics.current) == ("none", "none")


def test_an_incident_after_the_last_observation_still_sets_incident_peak_and_current():
    record = session(
        observations=(sle(10, {METRIC: 100}),),
        incidents=(IncidentRecord(event_type="AP_DISCONNECTED", occurred_at=minutes(50), severity="critical"),),
    )
    device = device_of(replay([record], selections=INCIDENT_SELECTION)[1])
    assert device.incidents is not None
    assert (device.incidents.peak, device.incidents.current) == ("critical", "critical")
    assert (device.peak, device.current) == ("critical", "critical")


@pytest.mark.parametrize(
    ("event_type", "occurred", "resolved", "peak", "current"),
    [
        pytest.param("AP_DISCONNECTED", minutes(5), None, "warning", "warning", id="unresolved"),
        pytest.param("AP_DISCONNECTED", minutes(5), minutes(30), "warning", "none", id="resolved before as_of"),
        pytest.param("AP_DISCONNECTED", minutes(5), AS_OF, "warning", "none", id="resolved at as_of"),
        pytest.param("AP_DISCONNECTED", minutes(5), minutes(121), "warning", "warning", id="resolved after as_of"),
        pytest.param("AP_DISCONNECTED", T0 - timedelta(seconds=1), None, "none", "none", id="before the change"),
        pytest.param(
            "AP_DISCONNECTED", T0 + timedelta(milliseconds=100), None, "warning", "warning", id="the change's second"
        ),
        pytest.param("AP_DISCONNECTED", AS_OF, None, "warning", "warning", id="at as_of"),
        pytest.param("AP_DISCONNECTED", minutes(121), None, "none", "none", id="after as_of"),
        pytest.param("SW_DISCONNECTED", minutes(5), None, "none", "none", id="not a selected incident type"),
    ],
)
def test_incident_peak_and_activity_at_as_of(event_type, occurred, resolved, peak, current):
    incident = IncidentRecord(event_type=event_type, occurred_at=occurred, severity="warning", resolved_at=resolved)
    device = device_of(replay([session(incidents=(incident,), completed=120)], selections=INCIDENT_SELECTION)[1])
    assert device.incidents is not None
    assert (device.incidents.peak, device.incidents.current) == (peak, current)


def finding(severity: str, kind: str = "port_down") -> FindingRecord:
    return FindingRecord(kind=kind, severity=severity)


@pytest.mark.parametrize(
    ("comparisons", "expected"),
    [
        pytest.param(
            (
                ComparisonRecord(
                    followup_at=minutes(6), findings=(finding("critical"),), latest_at=minutes(30), current_findings=()
                ),
            ),
            ("critical", "none"),
            id="recovered by the latest follow-up",
        ),
        pytest.param(
            (ComparisonRecord(followup_at=minutes(6), findings=(finding("warning"),)),),
            ("warning", "warning"),
            id="no later follow-up",
        ),
        pytest.param(
            (
                ComparisonRecord(
                    followup_at=minutes(6), findings=(finding("critical"),), latest_at=minutes(125), current_findings=()
                ),
            ),
            ("critical", "critical"),
            id="a recovery recorded after as_of",
        ),
        pytest.param(
            (ComparisonRecord(followup_at=minutes(121), findings=(finding("critical"),)),),
            None,
            id="a follow-up after as_of",
        ),
        pytest.param(
            (ComparisonRecord(followup_at=minutes(6), findings=(finding("critical", "cpu_util"),)),),
            ("none", "none"),
            id="not a selected finding kind",
        ),
        pytest.param(
            (
                ComparisonRecord(
                    followup_at=minutes(6), findings=(), latest_at=minutes(30), current_findings=(finding("critical"),)
                ),
            ),
            ("critical", "critical"),
            id="a finding that appeared later",
        ),
        pytest.param(
            (
                ComparisonRecord(
                    followup_at=minutes(6), findings=(finding("critical"),), latest_at=minutes(30), current_findings=()
                ),
                ComparisonRecord(followup_at=minutes(12), findings=(finding("warning"),)),
            ),
            ("critical", "warning"),
            id="two triggers",
        ),
    ],
)
def test_device_state_peak_from_initial_findings_and_current_from_current_findings(comparisons, expected):
    device = device_of(replay([session(comparisons=comparisons)], selections=FINDING_SELECTION)[1])
    component = device.device_state
    assert (None if component is None else (component.peak, component.current)) == expected


@pytest.mark.parametrize(
    ("metric", "incident", "finding_severity", "peak", "current"),
    [
        pytest.param((100, 100), None, None, "none", "none", id="nothing"),
        pytest.param((60, 100), None, None, "critical", "none", id="metric only"),
        pytest.param((100, 100), ("warning", None), None, "warning", "warning", id="incident only"),
        pytest.param((100, 100), None, "critical", "critical", "critical", id="device state only"),
        pytest.param((60, 100), ("warning", None), None, "critical", "warning", id="independent components"),
        pytest.param((100, 88), ("critical", 30), "warning", "critical", "warning", id="each component its own"),
    ],
)
def test_device_severity_is_the_maximum_of_independent_components(metric, incident, finding_severity, peak, current):
    observations = (sle(10, {METRIC: metric[0]}), sle(20, {METRIC: metric[1]}))
    incidents = (
        ()
        if incident is None
        else (
            IncidentRecord(
                event_type="AP_DISCONNECTED",
                occurred_at=minutes(25),
                severity=incident[0],
                resolved_at=None if incident[1] is None else minutes(incident[1]),
            ),
        )
    )
    comparisons = (
        ()
        if finding_severity is None
        else (ComparisonRecord(followup_at=minutes(6), findings=(finding(finding_severity),)),)
    )
    selections = {"dns": {"incident_types": ("AP_DISCONNECTED",), "finding_kinds": ("port_down",)}}
    device = device_of(
        replay(
            [session(observations=observations, incidents=incidents, comparisons=comparisons)], selections=selections
        )[1]
    )
    assert (device.peak, device.current) == (peak, current)
    components = [c for c in (device.metrics, device.incidents, device.device_state) if c is not None]
    assert device.peak == max((c.peak for c in components), key=band_rank)
    assert device.current == max((c.current for c in components), key=band_rank)


def test_selection_comes_from_the_devices_own_obligations():
    incidents = (IncidentRecord(event_type="SW_DISCONNECTED", occurred_at=minutes(5), severity="critical"),)
    comparisons = (ComparisonRecord(followup_at=minutes(6), findings=(finding("critical", "cpu_util"),)),)
    _, result = replay(
        [
            session(X, observations=(sle(10, {METRIC: 99, "coverage": 10}),), incidents=incidents),
            session(Y, observations=(sle(10, {METRIC: 99}, scope_id=Y),), comparisons=comparisons),
        ],
        obligation(X, owner="dns"),
        obligation(Y, owner="switch-port"),
        devices=((X, SITE), (Y, SITE)),
        selections={
            "dns": {"incident_types": ("AP_DISCONNECTED",), "finding_kinds": ("port_down",)},
            "switch-port": {"incident_types": ("SW_DISCONNECTED",), "finding_kinds": ("cpu_util",)},
        },
    )
    by_mac = {device.mac: device for device in result.devices}
    assert (by_mac[X].peak, by_mac[X].current) == ("none", "none")
    assert (by_mac[Y].peak, by_mac[Y].current) == ("critical", "critical")


def test_a_rule_obligation_selects_incidents_and_findings_without_metric_checks():
    incidents = (IncidentRecord(event_type="AP_DISCONNECTED", occurred_at=minutes(5), severity="warning"),)
    _, result = replay(
        [session(observations=(sle(10, {METRIC: 1}),), incidents=incidents)],
        obligation(kind="rule", owner="switch-port"),
        selections={"switch-port": {"incident_types": ("AP_DISCONNECTED",)}},
    )
    device = device_of(result)
    assert (device.checks, device.metrics) == ((), None)
    assert (device.peak, device.current) == ("warning", "warning")
    assert result.statuses == {}


def test_a_forced_final_run_replays_only_the_terminal_sessions_recorded_data():
    record = session(
        completed=60,
        observations=(sle(30, {METRIC: 50}), sle(60, {METRIC: 99})),
        incidents=(IncidentRecord(event_type="AP_DISCONNECTED", occurred_at=minutes(40), severity="warning"),),
    )
    ledger, result = replay([record], as_of=minutes(120), selections=INCIDENT_SELECTION)
    device = device_of(result)

    assert device.terminal is True
    assert status_of(ledger, result) == ObligationStatus(status="satisfied")
    [check] = device.checks
    assert check.value_after == 99
    assert device.metrics is not None
    assert device.incidents is not None
    assert (device.metrics.peak, device.metrics.current) == ("critical", "none")
    # Unresolved when the session ended, so still active at as_of.
    assert (device.incidents.peak, device.incidents.current) == ("warning", "warning")


@pytest.mark.parametrize("legacy", ["peak_impact_severity", "impact_severity", "assessment", "timeline"])
def test_stored_assessments_are_never_an_input(legacy):
    recorded = session().model_dump()
    with pytest.raises(ValidationError):
        MonitoringRecord.model_validate({**recorded, legacy: "critical"})


# Obligations -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("x", "y", "expected"),
    [
        pytest.param((100, 99), (100, 99), ObligationStatus(status="satisfied"), id="all satisfied"),
        pytest.param(
            ("no_data", "no_data"),
            ("no_data", "no_data"),
            ObligationStatus(status="not_exercised"),
            id="all not exercised",
        ),
        pytest.param((100, 99), ("no_data", "no_data"), ObligationStatus(status="satisfied"), id="mixed"),
        pytest.param(
            ("no_data", "no_data"),
            (100, "error"),
            ObligationStatus(status="unsatisfied", reason=f"The latest observation is error on {Y}"),
            id="one unsatisfied device",
        ),
        pytest.param(
            (100, "error"),
            (100, "missing"),
            ObligationStatus(
                status="unsatisfied", reason=f"The latest observation is error on {X} and 1 more device(s)"
            ),
            id="every device unsatisfied",
        ),
    ],
)
def test_a_site_level_obligation_resolves_over_every_device_at_its_site(x, y, expected):
    def record(mac: str, states: tuple[float | str, float | str], site: str = SITE) -> MonitoringRecord:
        baseline = sle(-1, {METRIC: states[0]}, scope_id=mac)
        return session(mac, site=site, baseline=baseline, observations=(sle(10, {METRIC: states[1]}, scope_id=mac),))

    ledger, result = replay(
        [record(X, x), record(Y, y), record(Z, (100, "error"), SITE_B)],
        obligation(Target(site_id=SITE), policy="not_exercised"),
        obligation(Target(device_mac=Z, site_id=SITE_B), owner="wlan-auth"),
        devices=((X, SITE), (Y, SITE), (Z, SITE_B)),
    )
    [site_level] = [o.id for o in ledger.obligations if o.kind == "monitoring" and o.target.device_mac is None]
    assert result.statuses[site_level] == expected
    assert result.reach[site_level] == (X, Y)


def test_statuses_cover_every_monitoring_obligation_with_its_own_empty_policy():
    no_data = sle(-1, {METRIC: "no_data", "coverage": "no_data"})
    ledger, result = replay(
        [session(baseline=no_data, observations=(sle(10, {METRIC: "no_data", "coverage": "no_data"}),))],
        obligation(policy="not_exercised"),
        obligation(metric="coverage", policy="incomplete", owner="wlan-auth"),
    )
    assert {o.id for o in ledger.obligations if o.kind == "monitoring"} == set(result.statuses)
    assert status_of(ledger, result).status == "not_exercised"
    assert status_of(ledger, result, "coverage") == ObligationStatus(status="unsatisfied", reason=NO_DATA_REASON)


def test_a_duplicate_obligation_merged_by_the_ledger_takes_the_strictest_policy():
    no_data = sle(-1, {METRIC: "no_data"})
    ledger, result = replay(
        [session(baseline=no_data, observations=(sle(10, {METRIC: "no_data"}),))],
        obligation(policy="not_exercised", owner="dns"),
        obligation(policy="incomplete", owner="wlan-auth"),
    )
    assert status_of(ledger, result) == ObligationStatus(status="unsatisfied", reason=NO_DATA_REASON)


def test_a_check_shows_the_strictest_treatment_while_each_obligation_keeps_its_own_policy():
    no_data = sle(-1, {METRIC: "no_data"})
    ledger, result = replay(
        [session(baseline=no_data, observations=(sle(10, {METRIC: "no_data"}),))],
        obligation(policy="not_exercised", owner="dns"),
        obligation(Target(site_id=SITE), policy="incomplete", owner="wlan-auth"),
    )
    [check] = device_of(result).checks
    assert (check.treatment, check.reason) == ("unsatisfied", NO_DATA_REASON)
    by_target = {o.target.device_mac: result.statuses[o.id] for o in ledger.obligations if o.kind == "monitoring"}
    assert by_target == {
        X: ObligationStatus(status="not_exercised"),
        None: ObligationStatus(status="unsatisfied", reason=NO_DATA_REASON),
    }


def test_a_target_naming_another_site_or_nothing_reaches_no_device():
    ledger, result = replay(
        [session(observations=(sle(10, {METRIC: 99}),))],
        obligation(Target(device_mac=X, site_id=SITE_B)),
        obligation(Target(device_mac=Y, site_id=SITE), owner="wlan-auth"),
        obligation(Target(), owner="switch-port"),
        devices=((X, SITE), (Y, SITE)),
    )
    for unreached in (Target(device_mac=X, site_id=SITE_B), Target()):
        found = next(o.id for o in ledger.obligations if o.kind == "monitoring" and o.target == unreached)
        assert result.reach[found] == ()
        assert result.statuses[found] == ObligationStatus(status="unsatisfied", reason=NO_DEVICE_REASON)
    assert [device.mac for device in result.devices] == [Y]


def test_a_device_target_outside_every_row_is_neither_evaluated_nor_counted():
    ledger, result = replay(
        [session(observations=(sle(10, {METRIC: 99}),)), session(Z, observations=(sle(10, {METRIC: 10}, scope_id=Z),))],
        obligation(X),
        obligation(Target(device_mac=Z, site_id=SITE), owner="wlan-auth"),
        selections={"wlan-auth": {"incident_types": ("AP_DISCONNECTED",)}},
    )
    outside = next(o.id for o in ledger.obligations if o.kind == "monitoring" and o.target.device_mac == Z)

    assert [device.mac for device in result.devices] == [X]
    assert [o.target.device_mac for o in ledger.obligations if o.kind == "deployment"] == [X]
    assert result.reach[outside] == ()
    assert result.statuses[outside] == ObligationStatus(status="unsatisfied", reason=NO_DEVICE_REASON)
    assert (result.peak, result.current) == ("none", "none")
    registry = EvidenceRegistry()
    conclusion = record_monitoring(result, frame=frame(), registry=registry)
    assert [item.scope.device_macs for item in registry.evidence] == [(X,)]
    assert conclusion.statuses[outside].evidence_ids == ()


# Evidence ----------------------------------------------------------------------------------------------------------


def three_devices() -> tuple[Ledger, MonitoringReplay]:
    receipts = [
        DeviceEventReceipt(
            receipt_id=f"t-{mac}",
            received_at=T0 + timedelta(seconds=4),
            event_type="AP_CONFIG_CHANGED_BY_USER",
            device_mac=mac,
            site_id=SITE,
            occurred_at=T0,
            audit_id=AUDIT,
        )
        for mac in (X, Y, Z)
    ]
    ledger, plans = setup(
        obligation(X, local="O1"),
        obligation(Y, local="O2"),
        obligation(Z, local="O3"),
        devices=((X, SITE), (Y, SITE), (Z, SITE)),
    )
    deployment = pair_deployments(receipts, frame=frame(), ledger=ledger)
    # Y is satisfied and Z unsatisfied, so priority, not MAC order, puts Z first.
    sessions = [
        session(Z, baseline=sle(-1, {METRIC: "no_data"}), observations=(sle(10, {METRIC: "no_data"}, scope_id=Z),)),
        session(Y, baseline=sle(-1, {METRIC: 100}, scope_id=Y), observations=(sle(10, {METRIC: 99}, scope_id=Y),)),
        session(X, observations=(sle(10, {METRIC: 40}),)),
    ]
    result = replay_monitoring(
        sessions,
        frame=frame(),
        ledger=ledger,
        plans=plans,
        expected=tuple(ExpectedDevice(mac=mac, site_id=SITE) for mac in (X, Y, Z)),
        deployment=deployment,
    )
    return ledger, result


def test_full_items_lead_with_warning_devices_then_unsatisfied_obligations_and_carry_the_checks():
    ledger, result = three_devices()
    registry = EvidenceRegistry()
    registry.reserve("deployment")
    conclusion = record_monitoring(result, frame=frame(), registry=registry)

    items = registry.evidence
    assert [(item.id, item.scope.device_macs) for item in items] == [("E2", (X,)), ("E3", (Z,)), ("E4", (Y,))]
    assert {item.source for item in items} == {"monitoring"}
    assert {item.kind for item in items} == {"service_health"}
    assert {item.representation for item in items} == {"full"}
    payload = items[0].payload
    assert payload["exclusive"] is True
    assert payload["deployment"] == "unknown"
    assert payload["deployment_precondition"] == "unsatisfied"
    [check] = payload["checks"]
    assert check == {
        "metric": METRIC,
        "before": "measured",
        "after": "measured",
        "value_before": 100.0,
        "value_after": 40.0,
        "delta": -60.0,
        "comparable": True,
        "treatment": "satisfied",
        "reason": None,
    }
    by_mac = {o.target.device_mac: o.id for o in ledger.obligations if o.kind == "monitoring"}
    assert {mac: conclusion.statuses[oid].evidence_ids for mac, oid in by_mac.items()} == {
        X: ("E2",),
        Y: ("E4",),
        Z: ("E3",),
    }
    assert [(d.mac, d.severity, d.evidence_ids) for d in conclusion.impacted_devices] == [(X, "critical", ("E2",))]
    assert (conclusion.peak, conclusion.current) == ("critical", "critical")


def test_below_warning_an_unsatisfied_device_comes_first_whatever_its_band():
    partial = sle(10, {METRIC: 99}, errors=("metric discovery: unavailable",))
    active = session(Y, baseline=sle(-1, {METRIC: 100}, scope_id=Y), active=True, completed=None)
    _, result = replay(
        [
            session(X, observations=(partial,)),
            active.model_copy(update={"observations": (sle(10, {METRIC: 99}, scope_id=Y),)}),
        ],
        obligation(X),
        obligation(Y, owner="wlan-auth"),
        devices=((X, SITE), (Y, SITE)),
    )
    by_mac = {device.mac: (device.status, device.peak) for device in result.devices}
    assert by_mac == {X: ("satisfied", "info"), Y: ("unsatisfied", "none")}
    registry = EvidenceRegistry()
    record_monitoring(result, frame=frame(), registry=registry)
    assert [item.scope.device_macs for item in registry.evidence] == [(Y,), (X,)]


def test_1000_devices_fit_the_monitoring_budget_with_a_digest_and_unchanged_statuses():
    macs = [f"02{number:010x}" for number in range(1_000)]
    devices = tuple((mac, SITE) for mac in macs)
    ledger, plans = setup(
        obligation(Target(site_id=SITE), policy="incomplete"),
        *(obligation(mac, metric="coverage", local=f"O{number}") for number, mac in enumerate(macs[:5], start=2)),
        devices=devices,
    )
    all_metrics = {METRIC: 40, "coverage": 99, "roaming": "no_data", "throughput": 99}
    sessions = [
        session(
            mac,
            baseline=sle(-1, {METRIC: 100, "coverage": 100, "roaming": "no_data", "throughput": 99}, scope_id=mac),
            observations=(sle(10, all_metrics if number % 7 == 0 else {**all_metrics, METRIC: 99}, scope_id=mac),),
            audits=(AUDIT,) if number % 5 else (AUDIT, OTHER),
        )
        for number, mac in enumerate(macs)
    ]
    result = replay_monitoring(
        sessions,
        frame=frame(),
        ledger=ledger,
        plans=plans,
        expected=tuple(ExpectedDevice(mac=mac, site_id=SITE) for mac in macs),
        deployment=DeploymentReplay(),
    )
    registry = EvidenceRegistry()
    conclusion = record_monitoring(result, frame=frame(), registry=registry)

    items = registry.evidence
    assert sum(json_size(item) for item in items) <= MONITORING_EVIDENCE_BUDGET
    *full, digest = items
    assert {item.representation for item in full} == {"full"}
    assert digest.representation == "digest"
    counts = digest.payload["devices"]
    assert isinstance(counts, dict)
    assert len(full) + sum(counts.values()) == 1_000
    peaks = [item.payload["peak"] for item in full]
    assert peaks == sorted(peaks, key=lambda band: -band_rank(band or "none"))
    assert all(peak == "critical" for peak in peaks)
    assert {name.split(":")[1] for name in counts} <= {"critical", "none", "unassessed"}
    stripped = {oid: status.model_copy(update={"evidence_ids": ()}) for oid, status in conclusion.statuses.items()}
    assert stripped == result.statuses
    [site_level] = [o.id for o in ledger.obligations if o.kind == "monitoring" and o.target.device_mac is None]
    assert conclusion.statuses[site_level].evidence_ids == tuple(item.id for item in items)


# The DNT-NTR monitoring projection ---------------------------------------------------------------------------------


def dnt_ntr_sessions() -> list[MonitoringRecord]:
    recorded = load_fixture("dnt_ntr_monitoring.json")
    sessions = []
    for item in recorded["sessions"]:
        before: dict[str, float | str] = {}
        after: dict[str, float | str] = {}
        for metric in item["metrics"]:
            before[metric["name"]] = metric["baseline"] if metric["baseline_state"] == "measured" else "no_data"
            after[metric["name"]] = metric["latest"] if metric["latest_state"] == "measured" else "no_data"
        started = datetime.fromisoformat(item["monitoring_started_at"])
        completed = datetime.fromisoformat(item["completed_at"])
        sessions.append(
            MonitoringRecord(
                session_id=item["session_id"],
                device_mac=item["device_mac"],
                site_id=recorded["site_id"],
                device_name=item["device_name"],
                audit_ids=tuple(item["audit_ids"]),
                created_at=datetime.fromisoformat(item["snapshot_at"]),
                active=item["monitoring_state"] not in {"completed", "failed"},
                completed_at=completed,
                baseline=sle(0, before, scope_id=item["device_mac"]).model_copy(update={"captured_at": started}),
                observations=(
                    sle(0, after, scope_id=item["device_mac"]).model_copy(update={"captured_at": completed}),
                ),
            )
        )
    return sessions


def test_the_dnt_ntr_monitoring_replays_without_a_floor_and_names_every_unsatisfied_check():
    recorded = load_fixture("dnt_ntr_monitoring.json")
    site = recorded["site_id"]
    sessions = dnt_ntr_sessions()
    metrics = {"SW": ("switch-health",), "AP": ("time-to-connect", "ap-health"), "GW": ("gateway-health",)}
    required = [
        (record.device_mac, metric, "incomplete" if record.device_name.startswith("SW") else "not_exercised")
        for record in sessions
        for metric in metrics[record.device_name[:2]]
    ]
    obligations = [
        obligation(Target(device_mac=mac, site_id=site), metric=metric, policy=policy, local=f"O{number}")
        for number, (mac, metric, policy) in enumerate(required, start=1)
    ]
    devices = tuple((s.device_mac, site) for s in sessions)
    ledger, plans = setup(*obligations, devices=devices)
    as_of = datetime(2026, 9, 16, 5, 42, 30, tzinfo=UTC)
    replay_frame = ReplayFrame(audit_id=AUDIT, anchor=RunAnchor(changed_at=CHANGED, source="audit"), as_of=as_of)
    result = replay_monitoring(
        sessions,
        frame=replay_frame,
        ledger=ledger,
        plans=plans,
        expected=tuple(ExpectedDevice(mac=mac, site_id=site) for mac, _ in devices),
        deployment=DeploymentReplay(),
    )

    assert all(device.exclusive and device.terminal for device in result.devices)
    unsatisfied = {
        (o.target.device_mac, o.metric): result.statuses[o.id].reason
        for o in ledger.obligations
        if o.kind == "monitoring" and result.statuses[o.id].status == "unsatisfied"
    }
    assert unsatisfied == {
        ("020000000011", "switch-health"): NO_DATA_REASON,
        ("020000000012", "switch-health"): NO_DATA_REASON,
        ("020000000013", "switch-health"): NO_DATA_REASON,
        ("020000000022", "time-to-connect"): DISAPPEARED_REASON,
    }
    assert band_rank(result.peak) < band_rank("warning")
    assert result.gaps == ()
