"""Post-configuration network impact monitoring models."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal

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


class RelevancePlan(BaseModel):
    """Explicit evidence selection. An empty selected plan selects nothing."""

    mode: Literal["selected", "legacy_all"] = "selected"
    metrics: list[str] = Field(default_factory=list)
    incident_types: list[str] = Field(default_factory=list)
    finding_kinds: list[str] = Field(default_factory=list)

    @classmethod
    def legacy_all(cls) -> "RelevancePlan":
        return cls(mode="legacy_all")


EvidenceState = Literal["measured", "no_data", "pending", "missing", "error", "unsupported", "disabled"]
EvidenceCoverage = Literal["complete", "partial", "insufficient", "not_applicable"]


class MetricEvidence(BaseModel):
    """A metric remains visible even when one or both values are unavailable."""

    name: str
    baseline: float | None = None
    latest: float | None = None
    delta: float | None = None
    baseline_state: EvidenceState = "missing"
    latest_state: EvidenceState = "missing"
    baseline_error: str | None = None
    latest_error: str | None = None
    comparable: bool = False
    selected: bool = True


class ImpactAssessment(BaseModel):
    """Authoritative evaluated result; legacy scalar fields are projections only."""

    version: Literal[1] = 1
    evaluated_at: datetime = Field(default_factory=utc_now)
    plan: RelevancePlan = Field(default_factory=RelevancePlan.legacy_all)
    severity: ImpactSeverity
    summary: str
    coverage: EvidenceCoverage = "insufficient"
    metrics: list[MetricEvidence] = Field(default_factory=list)
    collection_errors: list[str] = Field(default_factory=list)
    degraded_metrics: tuple[str, ...]
    metric_deltas: dict[str, float]
    incident_types: tuple[str, ...]
    device_findings: tuple[str, ...] = ()


class SleObservation(BaseModel):
    """Numeric SLE values captured over a bounded window."""

    captured_at: datetime = Field(default_factory=utc_now)
    scope: Literal["site", "device"] = "site"
    scope_id: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    values: dict[str, float] = Field(default_factory=dict)
    no_data: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    requested_metrics: list[str] = Field(default_factory=list)
    metric_errors: dict[str, str] = Field(default_factory=dict)
    metric_states: dict[str, EvidenceState] = Field(default_factory=dict)
    # Per-bucket success rates across the whole window, in provider order, with
    # None where a bucket carried no sampled traffic. Bucket instants are not
    # stored: every metric shares window_start/window_end, so a series of k
    # entries places bucket i at start + i * (end - start) / k. Legacy documents
    # have no trend and keep rendering as the single averaged value they are.
    trend: dict[str, list[float | None]] = Field(default_factory=dict)
    # Which part of the window `values` averages. Legacy documents predate the
    # anchored baseline and are truthfully described as full-window means.
    baseline_window: Literal["last-hour", "full-window"] = "full-window"


class MonitoringIncident(BaseModel):
    """Relevant device event observed after configuration."""

    event_type: str
    occurred_at: datetime = Field(default_factory=utc_now)
    severity: ImpactSeverity = ImpactSeverity.WARNING
    resolved: bool = False
    resolved_at: datetime | None = None


class MonitoringTimelineEvent(BaseModel):
    """Observed lifecycle evidence, never an inferred deployment milestone."""

    key: str
    event_type: str
    occurred_at: datetime
    received_at: datetime
    audit_id: str | None = None


class MonitoringSession(TimestampedModel, Document):
    """One active monitoring window for a changed device."""

    organization_id: PydanticObjectId
    audit_ids: list[str] = Field(default_factory=list)
    receipt_ids: list[PydanticObjectId] = Field(default_factory=list)
    timeline: list[MonitoringTimelineEvent] = Field(default_factory=list)
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
    relevance_plan: RelevancePlan = Field(default_factory=RelevancePlan.legacy_all)
    assessment: ImpactAssessment | None = None
    peak_impact_severity: ImpactSeverity = ImpactSeverity.NONE
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
            IndexModel([("organization_id", 1), ("site_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("audit_ids", 1)]),
            IndexModel([("organization_id", 1), ("receipt_ids", 1)]),
            IndexModel(
                [("organization_id", 1), ("device_mac", 1), ("active", 1)],
                unique=True,
                partialFilterExpression={"active": True},
                name="one_active_monitor_per_device",
            ),
        ]
