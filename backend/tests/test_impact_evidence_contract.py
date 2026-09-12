"""Selection, persisted verdict authority and evidence loss regression cases."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.models.monitoring import (
    DeviceType,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    MonitoringStatus,
    RelevancePlan,
    SleObservation,
)
from mist_config_guardian_backend.models.telemetry import DeviceStateFinding
from mist_config_guardian_backend.schemas.monitoring import MonitoringSessionResponse
from mist_config_guardian_backend.services import monitoring
from mist_config_guardian_backend.services.impact_analysis import assess_impact, store_assessment
from mist_config_guardian_backend.services.monitoring import MonitoringEventService
from mist_config_guardian_backend.services.site_impact import impact_from_session

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def test_explicit_empty_plan_does_not_fall_back_to_all_evidence():
    result = assess_impact(
        SleObservation(values={"ap-health": 99}),
        SleObservation(values={"ap-health": 0}),
        [MonitoringIncident(event_type="AP_DISCONNECTED", severity=ImpactSeverity.CRITICAL)],
        relevance_plan=RelevancePlan(),
        device_findings=[
            DeviceStateFinding(
                kind="device_disconnected",
                subject="ap",
                before="up",
                after="down",
                detail="Offline",
                severity="critical",
            )
        ],
    )
    assert result.severity == ImpactSeverity.INFO
    assert result.coverage == "not_applicable"
    assert result.metric_deltas == {}
    assert result.incident_types == result.device_findings == ()
    assert not result.metrics[0].selected


def test_selected_metrics_ignore_unrelated_degradation_and_collection_errors():
    result = assess_impact(
        SleObservation(values={"ap-health": 99, "successful-connect": 99}),
        SleObservation(values={"ap-health": 0, "successful-connect": 99}, errors=["coverage: HTTP 404"]),
        [],
        relevance_plan=RelevancePlan(metrics=["successful-connect"]),
    )
    assert result.severity == ImpactSeverity.NONE
    assert result.coverage == "complete"
    assert result.metric_deltas == {"successful-connect": 0}
    assert len(result.metrics) == 3
    assert result.collection_errors == ["Latest: coverage: HTTP 404"]


def test_incidents_and_findings_are_selected_independently():
    incident = MonitoringIncident(event_type="AP_DISCONNECTED", severity=ImpactSeverity.CRITICAL)
    finding = DeviceStateFinding(
        kind="poe_power_lost", subject="port1", before="on", after="off", detail="Power lost", severity="critical"
    )
    for plan in [RelevancePlan(incident_types=[incident.event_type]), RelevancePlan(finding_kinds=[finding.kind])]:
        result = assess_impact(None, None, [incident], device_findings=[finding], relevance_plan=plan)
        assert result.severity == ImpactSeverity.CRITICAL
        assert bool(result.incident_types) != bool(result.device_findings)


@pytest.mark.parametrize("state", ["no_data", "pending", "missing", "error", "unsupported", "disabled"])
def test_planned_metric_without_numeric_values_stays_visible(state):
    result = assess_impact(
        None, SleObservation(metric_states={"coverage": state}), [], relevance_plan=RelevancePlan(metrics=["coverage"])
    )
    row = result.metrics[0]
    assert row.name == "coverage"
    assert row.latest_state == state
    assert row.baseline_state == "pending"
    assert row.baseline is row.latest is row.delta is None
    assert result.severity == ImpactSeverity.INFO


def test_error_only_metric_and_discovery_error_are_not_confused():
    result = assess_impact(
        SleObservation(errors=["metric discovery: HTTP 403"]),
        SleObservation(
            errors=["roaming: HTTP 404"],
            requested_metrics=["coverage", "roaming"],
            metric_errors={"roaming": "roaming: HTTP 404"},
        ),
        [],
    )
    assert [row.name for row in result.metrics] == ["coverage", "roaming"]
    assert result.metrics[1].latest_state == "error"
    assert len(result.collection_errors) == 2
    assert result.severity == ImpactSeverity.INFO


def test_measured_zero_is_an_outage_and_different_scope_ids_are_not_comparable():
    before = SleObservation(scope="device", scope_id="ap1", values={"coverage": 99})
    after = SleObservation(scope="device", scope_id="ap1", values={"coverage": 0})
    result = assess_impact(before, after, [])
    assert result.metrics[0].latest == 0
    assert result.metrics[0].latest_state == "measured"
    assert result.severity == ImpactSeverity.CRITICAL
    after.scope_id = "ap2"
    assert assess_impact(before, after, []).metrics[0].delta is None


def _session():
    return MonitoringSession.model_construct(
        id=PydanticObjectId(),
        organization_id=PydanticObjectId(),
        device_mac="aabbccddeeff",
        site_id="site",
        device_type=DeviceType.AP,
        baseline=SleObservation(values={"coverage": 99}),
        observations=[SleObservation(values={"coverage": 99})],
    )


def test_both_api_views_use_stored_result_even_when_legacy_mirrors_disagree():
    session = _session()
    result = assess_impact(session.baseline, session.observations[-1], [])
    result.evaluated_at = NOW
    store_assessment(session, result)
    session.impact_severity = ImpactSeverity.CRITICAL
    session.deterministic_summary = "Stale mirror"
    session.observations[-1].values = {"coverage": 0}
    response = MonitoringSessionResponse.from_document(session)
    assert response.impact_severity == ImpactSeverity.NONE
    assert response.assessment_source == "stored"
    assert response.deterministic_summary == result.summary
    row = session.model_dump()
    row["_id"] = session.id
    impact = impact_from_session(row, NOW, historical=False)
    assert impact.severity == "ok"
    assert impact.metrics[0].latest == 99
    assert impact.assessment_source == "stored"
    assert impact_from_session(row, NOW, historical=True).severity == "unknown"
    row["assessment"]["collection_errors"] = ["Latest: future collection failure"]
    assert impact_from_session(row, NOW, historical=True).collection_errors == []


async def test_webhook_incident_and_recovery_update_authoritative_result(monkeypatch):
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())
    session = _session()
    await MonitoringEventService._record_incident(session, "AP_DISCONNECTED")  # noqa: SLF001
    assert session.assessment is not None
    assert session.assessment.severity == session.impact_severity == ImpactSeverity.WARNING
    MonitoringEventService._resolve_incidents(session, "AP_CONNECTED")  # noqa: SLF001
    assert session.assessment.severity == session.impact_severity == ImpactSeverity.NONE
    assert session.assessment.incident_types == ()
    assert session.peak_impact_severity == ImpactSeverity.WARNING


@pytest.mark.parametrize(
    ("event_type", "summary"),
    [
        ("AP_CONFIG_FAILED", "The configuration failed before monitoring could begin."),
        ("SW_CONFIG_REVERTED", "The configuration was reverted; monitoring for this change has ended."),
    ],
)
async def test_terminal_summary_is_stored_even_when_assessment_is_copied(monkeypatch, event_type, summary):
    monkeypatch.setattr(MonitoringSession, "save", AsyncMock())

    def copy_assessment(session, assessment):
        store_assessment(session, assessment.model_copy(deep=True))

    monkeypatch.setattr(monitoring, "store_assessment", copy_assessment)
    session = _session()
    session.status = MonitoringStatus.AWAITING_CONFIG
    await MonitoringEventService._record_incident(session, event_type)  # noqa: SLF001
    assert session.status == MonitoringStatus.FAILED
    assert session.assessment.summary == session.deterministic_summary == summary
    assert MonitoringSessionResponse.from_document(session).deterministic_summary == summary


@pytest.mark.parametrize(
    ("severity", "health"),
    [(ImpactSeverity.INFO, "error"), (ImpactSeverity.WARNING, "error"), (ImpactSeverity.CRITICAL, "critical")],
)
def test_failed_stored_assessment_remains_filterable_without_masking_critical(severity, health):
    session = _session()
    session.status = MonitoringStatus.FAILED
    session.completed_at = NOW
    assessment = assess_impact(None, None, [])
    assessment.severity = severity
    assessment.evaluated_at = NOW
    store_assessment(session, assessment)
    row = session.model_dump()
    row["_id"] = session.id
    result = impact_from_session(row, NOW, historical=False)
    assert result.severity == health
    assert result.monitoring_state == "aborted"
    assert session.assessment.severity == severity
    assert impact_from_session(row, NOW, historical=True).severity == "unknown"


def test_legacy_projection_preserves_alarm_and_exposes_missing_metric_in_both_views():
    session = _session()
    session.baseline.values["capacity"] = 99
    session.impact_severity = ImpactSeverity.WARNING
    response = MonitoringSessionResponse.from_document(session)
    row = session.model_dump()
    row["_id"] = session.id
    impact = impact_from_session(row, datetime.now(UTC), historical=False)
    assert response.impact_severity == ImpactSeverity.WARNING
    assert impact.severity == "warning"
    assert response.assessment.coverage == impact.evidence_coverage == "partial"
    assert impact.metrics[0].latest_state == "missing"
