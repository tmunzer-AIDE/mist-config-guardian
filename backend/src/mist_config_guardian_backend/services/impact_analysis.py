"""Deterministic and provider-neutral impact analysis."""

from dataclasses import dataclass
from typing import Protocol

from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringIncident,
    SleObservation,
)


@dataclass(frozen=True)
class ImpactAssessment:
    """Secret-safe deterministic assessment input and result."""

    severity: ImpactSeverity
    summary: str
    degraded_metrics: tuple[str, ...]
    metric_deltas: dict[str, float]
    incident_types: tuple[str, ...]


class AiImpactProvider(Protocol):
    """Optional provider adapter consuming only deterministic, secret-safe data."""

    async def assess(self, assessment: ImpactAssessment) -> dict[str, object]:
        """Return a structured supplemental assessment."""
        ...


def assess_impact(
    baseline: SleObservation | None,
    latest: SleObservation | None,
    incidents: list[MonitoringIncident],
    *,
    warning_threshold: float = 10.0,
    critical_threshold: float = 25.0,
) -> ImpactAssessment:
    """Classify impact from SLE deltas and unresolved incidents."""
    deltas: dict[str, float] = {}
    if baseline is not None and latest is not None:
        for metric, baseline_value in baseline.values.items():
            current = latest.values.get(metric)
            if current is not None:
                deltas[metric] = round(current - baseline_value, 2)

    degraded = tuple(sorted(metric for metric, delta in deltas.items() if delta <= -warning_threshold))
    unresolved = [incident for incident in incidents if not incident.resolved]
    critical_incident = any(incident.severity is ImpactSeverity.CRITICAL for incident in unresolved)
    critical_metric = any(delta <= -critical_threshold for delta in deltas.values())
    if critical_incident or critical_metric:
        severity = ImpactSeverity.CRITICAL
    elif unresolved or degraded:
        severity = ImpactSeverity.WARNING
    elif deltas:
        severity = ImpactSeverity.NONE
    else:
        severity = ImpactSeverity.INFO

    if severity is ImpactSeverity.CRITICAL:
        summary = "Critical degradation detected after the configuration change."
    elif severity is ImpactSeverity.WARNING:
        summary = "Potential negative impact detected after the configuration change."
    elif severity is ImpactSeverity.NONE:
        summary = "No negative impact was detected during the monitoring window."
    else:
        summary = "Monitoring completed with insufficient SLE data for a full comparison."
    return ImpactAssessment(
        severity=severity,
        summary=summary,
        degraded_metrics=degraded,
        metric_deltas=deltas,
        incident_types=tuple(sorted(incident.event_type for incident in unresolved)),
    )
