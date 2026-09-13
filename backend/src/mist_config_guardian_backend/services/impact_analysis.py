"""Deterministic and provider-neutral impact analysis."""

from collections.abc import Sequence
from typing import Protocol

from mist_config_guardian_backend.models.monitoring import (
    ImpactAssessment,
    ImpactSeverity,
    MonitoringIncident,
    MonitoringSession,
    RelevancePlan,
    SleObservation,
)
from mist_config_guardian_backend.models.telemetry import DeviceStateFinding
from mist_config_guardian_backend.services.impact_evidence import collection_errors, evidence_coverage, evidence_rows


class AiImpactProvider(Protocol):
    """Optional provider adapter consuming only deterministic, secret-safe data."""

    async def assess(self, assessment: ImpactAssessment) -> dict[str, object]:
        """Return a structured supplemental assessment."""
        ...


def assess_impact(  # noqa: PLR0913 - evidence inputs and configurable thresholds
    baseline: SleObservation | None,
    latest: SleObservation | None,
    incidents: list[MonitoringIncident],
    *,
    relevance_plan: RelevancePlan | None = None,
    device_findings: Sequence[DeviceStateFinding] = (),
    warning_threshold: float = 10.0,
    critical_threshold: float = 25.0,
) -> ImpactAssessment:
    """Classify impact from SLE deltas and unresolved incidents."""
    plan = relevance_plan if relevance_plan is not None else RelevancePlan.legacy_all()
    rows = evidence_rows(baseline, latest, plan)
    coverage = evidence_coverage(rows, baseline, latest, plan)
    deltas = {row.name: row.delta for row in rows if row.selected and row.delta is not None}
    device_findings = [
        finding for finding in device_findings if plan.mode == "legacy_all" or finding.kind in plan.finding_kinds
    ]

    degraded = tuple(sorted(metric for metric, delta in deltas.items() if delta <= -warning_threshold))
    unresolved = [
        incident
        for incident in incidents
        if not incident.resolved and (plan.mode == "legacy_all" or incident.event_type in plan.incident_types)
    ]
    critical_incident = any(incident.severity is ImpactSeverity.CRITICAL for incident in unresolved)
    critical_metric = any(delta <= -critical_threshold for delta in deltas.values())
    if critical_incident or critical_metric or any(f.severity == "critical" for f in device_findings):
        severity = ImpactSeverity.CRITICAL
    elif unresolved or degraded or device_findings:
        severity = ImpactSeverity.WARNING
    elif deltas and coverage == "complete":
        severity = ImpactSeverity.NONE
    else:
        severity = ImpactSeverity.INFO

    summary = _summary(severity, device_findings)
    if severity is ImpactSeverity.NONE and ((baseline and baseline.no_data) or (latest and latest.no_data)):
        summary += " Metrics with no sampled traffic were excluded from numeric comparisons."

    return ImpactAssessment(
        plan=plan.model_copy(deep=True),
        coverage=coverage,
        metrics=rows,
        collection_errors=collection_errors(baseline, latest),
        severity=severity,
        summary=summary,
        degraded_metrics=degraded,
        metric_deltas=deltas,
        incident_types=tuple(sorted(incident.event_type for incident in unresolved)),
        device_findings=tuple(finding.detail for finding in device_findings),
    )


def _summary(severity: ImpactSeverity, findings: Sequence[DeviceStateFinding]) -> str:
    descriptions = {
        ImpactSeverity.CRITICAL: "Critical degradation detected after the configuration change.",
        ImpactSeverity.WARNING: "Potential negative impact detected after the configuration change.",
        ImpactSeverity.NONE: "No negative impact was detected during the monitoring window.",
        ImpactSeverity.INFO: "Insufficient SLE evidence to assess network health; this is not a healthy verdict.",
    }
    summary = descriptions[severity]
    if findings:
        summary += f" {len(findings)} operational differences detected at the five-minute comparison."
    return summary


def store_assessment(session: MonitoringSession, assessment: ImpactAssessment) -> None:
    """Write the authoritative result and its backwards-compatible scalar mirrors."""
    session.assessment = assessment
    session.impact_severity = assessment.severity
    session.deterministic_summary = assessment.summary
    session.degraded_metrics = list(assessment.degraded_metrics)
