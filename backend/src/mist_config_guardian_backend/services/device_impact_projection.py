"""Shared, evidence-safe device projection for site and change workspaces."""

from datetime import UTC, datetime
from typing import Any, cast

from mist_config_guardian_backend.integrations.mist_topology import normalized_mac
from mist_config_guardian_backend.models.monitoring import ImpactAssessment, ImpactSeverity, SleObservation
from mist_config_guardian_backend.schemas.impact import DeviceImpact, Health, ImpactMetric
from mist_config_guardian_backend.services.impact_evidence import legacy_assessment, validate_zero_evidence


def as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def impact_from_session(row: dict[str, Any], end: datetime, *, historical: bool) -> DeviceImpact:
    def at(key: str) -> datetime | None:
        value = row.get(key)
        return as_utc(value) if isinstance(value, datetime) and as_utc(value) <= end else None

    observations = [sample for sample in row.get("observations", []) if as_utc(sample["captured_at"]) <= end]
    baseline = row.get("baseline") or {}
    if baseline.get("captured_at") and as_utc(baseline["captured_at"]) > end:
        baseline = {}
    latest = observations[-1] if observations else {}
    stored = ImpactAssessment.model_validate(row["assessment"]) if row.get("assessment") else None
    if stored and (historical or as_utc(stored.evaluated_at) > end):
        stored = None
    assessment = (
        stored
        if stored is not None
        else legacy_assessment(
            SleObservation.model_validate(baseline) if baseline else None,
            SleObservation.model_validate(latest) if latest else None,
            ImpactSeverity(row.get("impact_severity", "info")),
            row.get("deterministic_summary"),
            incident_types=tuple(
                incident["event_type"] for incident in row.get("incidents", []) if not incident.get("resolved")
            ),
            device_findings=tuple(finding["detail"] for finding in row.get("device_findings", [])),
        )
    )
    assessment = validate_zero_evidence(
        assessment,
        SleObservation.model_validate(baseline) if baseline else None,
        SleObservation.model_validate(latest) if latest else None,
    )
    metrics = [ImpactMetric.model_validate(metric, from_attributes=True) for metric in assessment.metrics]
    errors = assessment.collection_errors
    measured = any(metric.comparable and metric.selected for metric in metrics)
    configured, started, completed = at("config_applied_at"), at("monitoring_started_at"), at("completed_at")
    ends = row.get("monitoring_ends_at")
    ends = as_utc(ends) if isinstance(ends, datetime) else None
    rolled_back = any(
        event["event_type"].endswith("_CONFIG_REVERTED") and as_utc(event["received_at"]) <= end
        for event in row.get("timeline", [])
    )
    config = "rolled_back" if rolled_back else "applied" if configured else "pending"
    state = "not_started"
    if started:
        state = (
            "completed"
            if completed and measured and not errors and row.get("status") != "failed"
            else "aborted"
            if completed
            else "stalled"
            if not measured or errors
            else "monitoring"
        )
    elif completed:
        state = "aborted"
    percentage = 0
    if started and ends and ends > started:
        percentage = min(
            100, max(0, round(((completed or end) - started).total_seconds() / (ends - started).total_seconds() * 100))
        )
    severity = {"none": "ok", "info": "unknown", "warning": "warning", "critical": "critical"}.get(
        assessment.severity, "unknown"
    )
    # Lifecycle failure stays filterable without hiding a critical impact verdict.
    if row.get("status") == "failed" and severity != "critical":
        severity = "error"
    headline = assessment.summary
    if historical:
        severity, headline = "unknown", "Historical lifecycle evidence; the verdict at this instant was not retained."
    snapshots = [
        as_utc(value) for value in row.get("snapshot_times", []) if isinstance(value, datetime) and as_utc(value) <= end
    ]
    return DeviceImpact(
        device_id=normalized_mac(row["device_mac"]),
        device_name=row.get("device_name") or row["device_mac"],
        session_id=str(row["_id"]),
        severity=cast("Health", severity),
        config_state=config,
        detected_at=at("change_triggered_at"),
        snapshot_at=min(snapshots) if snapshots else None,
        configured_at=configured,
        monitoring_started_at=started,
        monitoring_ends_at=ends,
        completed_at=completed,
        monitoring_state=state,
        progress=percentage,
        observation_count=len(observations),
        headline=headline,
        metrics=[] if historical else metrics,
        evidence_coverage="insufficient" if historical else assessment.coverage,
        assessment_source="historical" if historical else "stored" if stored else "legacy",
        collection_errors=errors,
        shared_window=len(row.get("audit_ids", [])) > 1,
    )
