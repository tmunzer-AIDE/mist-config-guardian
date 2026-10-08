"""Reconcile deployment failures with observed, later success on the same session."""

from collections.abc import Sequence
from datetime import UTC, datetime

from mist_config_guardian_backend.models.monitoring import (
    MonitoringIncident,
    MonitoringSession,
    MonitoringTimelineEvent,
)
from mist_config_guardian_backend.services.impact_analysis import assess_impact, store_assessment

_SUCCESSES = {
    "AP_CONFIG_FAILED": "AP_CONFIGURED",
    "SW_CONFIG_FAILED": "SW_CONFIGURED",
    "GW_CONFIG_FAILED": "GW_CONFIGURED",
}


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def recovered_incidents(
    incidents: Sequence[MonitoringIncident], timeline: Sequence[MonitoringTimelineEvent]
) -> list[MonitoringIncident] | None:
    """Return corrected copies only when a later, observed deployment succeeded.

    Legacy incidents used receipt time. When every failure has its event in the
    ledger, pair the two arrival-ordered lists to recover the provider event time.
    Ambiguous ledgers keep the original incident timestamp. A success before a
    failure, another device's history, or a revert cannot close that failure.
    """
    result = list(incidents)
    changed = False
    for failed, configured in _SUCCESSES.items():
        indices = [index for index, incident in enumerate(incidents) if incident.event_type == failed]
        failures = [event for event in timeline if event.event_type == failed]
        successes = sorted(_utc(event.occurred_at) for event in timeline if event.event_type == configured)
        for position, index in enumerate(indices):
            incident = incidents[index]
            if incident.resolved:
                continue
            occurred = (
                _utc(failures[position].occurred_at) if len(failures) == len(indices) else _utc(incident.occurred_at)
            )
            resolved = next((at for at in successes if at > occurred), None)
            if resolved is None:
                continue
            result[index] = incident.model_copy(
                update={"occurred_at": occurred, "resolved": True, "resolved_at": resolved}
            )
            changed = True
    return result if changed else None


def reconciled_session(session: MonitoringSession) -> MonitoringSession:
    """Correct a read without changing its shared document or erasing peak impact."""
    incidents = recovered_incidents(session.incidents, session.timeline)
    if incidents is None:
        return session
    clean = session.model_copy(deep=True)
    clean.incidents = incidents
    store_assessment(
        clean,
        assess_impact(
            clean.baseline,
            clean.observations[-1] if clean.observations else None,
            clean.incidents,
            relevance_plan=clean.assessment.plan if clean.assessment else clean.relevance_plan,
            device_findings=clean.device_findings,
        ),
    )
    return clean
