"""Post-configuration network impact monitoring models."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel, utc_now
from mist_config_guardian_backend.models.telemetry import DeviceStateComparison, DeviceStateFinding


class DeviceType(StrEnum):
    """Mist infrastructure device type."""

    AP = "ap"
    SWITCH = "switch"
    GATEWAY = "gateway"


class MonitoringStatus(StrEnum):
    """Monitoring lifecycle."""

    AWAITING_CONFIG = "awaiting_config"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    FAILED = "failed"


class ImpactSeverity(StrEnum):
    """Deterministic or AI-assisted impact rating."""

    NONE = "none"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class SleObservation(BaseModel):
    """Numeric SLE values captured over a bounded window."""

    captured_at: datetime = Field(default_factory=utc_now)
    window_start: datetime | None = None
    window_end: datetime | None = None
    values: dict[str, float] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class MonitoringIncident(BaseModel):
    """Relevant device event observed after configuration."""

    event_type: str
    occurred_at: datetime = Field(default_factory=utc_now)
    severity: ImpactSeverity = ImpactSeverity.WARNING
    resolved: bool = False
    resolved_at: datetime | None = None


class MonitoringSession(TimestampedModel, Document):
    """One active monitoring window for a changed device."""

    organization_id: PydanticObjectId
    audit_ids: list[str] = Field(default_factory=list)
    receipt_ids: list[PydanticObjectId] = Field(default_factory=list)
    site_id: str
    device_mac: str
    device_name: str = ""
    device_type: DeviceType
    status: MonitoringStatus = MonitoringStatus.AWAITING_CONFIG
    active: bool = True
    baseline: SleObservation | None = None
    change_triggered_at: datetime | None = None
    device_comparisons: list[DeviceStateComparison] = Field(default_factory=list)
    device_findings: list[DeviceStateFinding] = Field(default_factory=list)
    observations: list[SleObservation] = Field(default_factory=list)
    incidents: list[MonitoringIncident] = Field(default_factory=list)
    config_applied_at: datetime | None = None
    monitoring_started_at: datetime | None = None
    monitoring_ends_at: datetime | None = None
    next_poll_at: datetime | None = None
    impact_severity: ImpactSeverity = ImpactSeverity.NONE
    deterministic_summary: str | None = None
    degraded_metrics: list[str] = Field(default_factory=list)
    ai_assessment: dict[str, object] | None = None
    ai_assessment_error: str | None = None
    completed_at: datetime | None = None
    warnings: list[str] = Field(default_factory=list)

    class Settings:
        name = "monitoring_sessions"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("status", 1)]),
            IndexModel([("organization_id", 1), ("audit_ids", 1)]),
            IndexModel([("organization_id", 1), ("receipt_ids", 1)]),
            IndexModel(
                [("organization_id", 1), ("device_mac", 1), ("active", 1)],
                unique=True,
                partialFilterExpression={"active": True},
                name="one_active_monitor_per_device",
            ),
        ]
