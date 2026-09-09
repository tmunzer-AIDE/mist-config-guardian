"""Deterministic and provider-neutral impact analysis."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringIncident,
    SleObservation,
)
from mist_config_guardian_backend.models.telemetry import DeviceStateFinding


@dataclass(frozen=True)
class ImpactAssessment:
    """Secret-safe deterministic assessment input and result."""

    severity: ImpactSeverity
    summary: str
    degraded_metrics: tuple[str, ...]
    metric_deltas: dict[str, float]
    incident_types: tuple[str, ...]
    device_findings: tuple[str, ...] = ()


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
    device_findings: Sequence[DeviceStateFinding] = (),
    warning_threshold: float = 10.0,
    critical_threshold: float = 25.0,
) -> ImpactAssessment:
    """Classify impact from SLE deltas and unresolved incidents."""
    deltas: dict[str, float] = {}
    if baseline is not None and latest is not None and baseline.scope == latest.scope:
        for metric, baseline_value in baseline.values.items():
            current = latest.values.get(metric)
            if current is not None:
                deltas[metric] = round(current - baseline_value, 2)

    degraded = tuple(sorted(metric for metric, delta in deltas.items() if delta <= -warning_threshold))
    unresolved = [incident for incident in incidents if not incident.resolved]
    critical_incident = any(incident.severity is ImpactSeverity.CRITICAL for incident in unresolved)
    critical_metric = any(delta <= -critical_threshold for delta in deltas.values())
    if critical_incident or critical_metric or any(f.severity == "critical" for f in device_findings):
        severity = ImpactSeverity.CRITICAL
    elif unresolved or degraded or device_findings:
        severity = ImpactSeverity.WARNING
    elif deltas and _complete_sle_comparison(baseline, latest):
        severity = ImpactSeverity.NONE
    else:
        severity = ImpactSeverity.INFO

    summary = _summary(severity, device_findings)
    if severity is ImpactSeverity.NONE and ((baseline and baseline.no_data) or (latest and latest.no_data)):
        summary += " Metrics with no sampled traffic were excluded from numeric comparisons."

    return ImpactAssessment(
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


def _complete_sle_comparison(baseline: SleObservation | None, latest: SleObservation | None) -> bool:
    return bool(
        baseline
        and latest
        and baseline.scope == latest.scope
        and not baseline.errors
        and not latest.errors
        and (set(baseline.values) | set(baseline.no_data))
        and (set(baseline.values) | set(baseline.no_data)) == (set(latest.values) | set(latest.no_data))
    )
