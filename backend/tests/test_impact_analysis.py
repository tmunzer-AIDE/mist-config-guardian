"""Deterministic impact assessment tests."""

from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringIncident,
    SleObservation,
)
from mist_config_guardian_backend.services.impact_analysis import assess_impact


def test_assessment_reports_critical_metric_degradation() -> None:
    assessment = assess_impact(
        SleObservation(values={"coverage": 98.0, "capacity": 95.0}),
        SleObservation(values={"coverage": 70.0, "capacity": 96.0}),
        [],
    )

    assert assessment.severity is ImpactSeverity.CRITICAL
    assert assessment.degraded_metrics == ("coverage",)
    assert assessment.metric_deltas == {"coverage": -28.0, "capacity": 1.0}


def test_assessment_ignores_resolved_incident() -> None:
    assessment = assess_impact(
        SleObservation(values={"switch-health": 95.0}),
        SleObservation(values={"switch-health": 94.0}),
        [
            MonitoringIncident(
                event_type="SW_DISCONNECTED",
                severity=ImpactSeverity.CRITICAL,
                resolved=True,
            )
        ],
    )

    assert assessment.severity is ImpactSeverity.NONE
    assert assessment.incident_types == ()


def test_assessment_handles_missing_baseline() -> None:
    assessment = assess_impact(None, SleObservation(values={}), [])

    assert assessment.severity is ImpactSeverity.INFO
