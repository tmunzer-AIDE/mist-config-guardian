"""Network impact monitoring API schemas."""

from datetime import datetime

from pydantic import BaseModel

from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringSession,
    MonitoringStatus,
)


class SleObservationResponse(BaseModel):
    """Safe numeric SLE observation."""

    captured_at: datetime
    values: dict[str, float]
    errors: list[str]


class MonitoringIncidentResponse(BaseModel):
    """Relevant event observed in a monitoring window."""

    event_type: str
    occurred_at: datetime
    severity: ImpactSeverity
    resolved: bool
    resolved_at: datetime | None


class MonitoringSessionResponse(BaseModel):
    """Complete monitoring session with no credentials or raw payloads."""

    id: str
    audit_ids: list[str]
    site_id: str
    device_mac: str
    device_name: str
    device_type: str
    status: MonitoringStatus
    baseline: SleObservationResponse | None
    observations: list[SleObservationResponse]
    incidents: list[MonitoringIncidentResponse]
    config_applied_at: datetime | None
    monitoring_started_at: datetime | None
    monitoring_ends_at: datetime | None
    impact_severity: ImpactSeverity
    deterministic_summary: str | None
    degraded_metrics: list[str]
    ai_assessment: dict[str, object] | None
    ai_assessment_error: str | None
    warnings: list[str]
    created_at: datetime
    completed_at: datetime | None

    @classmethod
    def from_document(cls, session: MonitoringSession) -> "MonitoringSessionResponse":
        """Convert a persisted session into its safe API shape."""
        if session.id is None:
            msg = "Persisted monitoring session is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(session.id),
            audit_ids=list(session.audit_ids),
            site_id=session.site_id,
            device_mac=session.device_mac,
            device_name=session.device_name,
            device_type=session.device_type,
            status=session.status,
            baseline=(
                SleObservationResponse.model_validate(session.baseline, from_attributes=True)
                if session.baseline
                else None
            ),
            observations=[
                SleObservationResponse.model_validate(item, from_attributes=True) for item in session.observations
            ],
            incidents=[
                MonitoringIncidentResponse.model_validate(item, from_attributes=True) for item in session.incidents
            ],
            config_applied_at=session.config_applied_at,
            monitoring_started_at=session.monitoring_started_at,
            monitoring_ends_at=session.monitoring_ends_at,
            impact_severity=session.impact_severity,
            deterministic_summary=session.deterministic_summary,
            degraded_metrics=list(session.degraded_metrics),
            ai_assessment=session.ai_assessment,
            ai_assessment_error=session.ai_assessment_error,
            warnings=list(session.warnings),
            created_at=session.created_at,
            completed_at=session.completed_at,
        )


class MonitoringSessionListResponse(BaseModel):
    """Paginated monitoring session collection."""

    items: list[MonitoringSessionResponse]
    total: int
