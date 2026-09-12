"""Change-group read-model API schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mist_config_guardian_backend.models.monitoring import ImpactSeverity
from mist_config_guardian_backend.models.webhook import (
    BaselineConfidence,
    ChangeSource,
    RecoveryState,
)
from mist_config_guardian_backend.schemas.audit_impact import AuditImpactSummary


class ChangedObjectResponse(BaseModel):
    """One configuration object an administrator action touched."""

    logical_object_id: str
    object_type: str
    object_name: str
    scope: str
    site_mist_id: str | None = None
    event: str
    before_version_id: str | None = None
    after_version_id: str | None = None
    before_version: int | None = None
    after_version: int | None = None
    changed_fields: list[str] = Field(default_factory=list)


class AffectedDeviceResponse(BaseModel):
    """One device that received configuration from a change group."""

    device_mac: str
    device_name: str = ""
    device_type: str = ""
    site_mist_id: str = ""


class ChangeEvidenceResponse(BaseModel):
    """One deterministic statement supporting a group's assessment."""

    label: str
    severity: ImpactSeverity = ImpactSeverity.NONE


class ChangeMetricResponse(BaseModel):
    """One metric tile rendered on an Overview feed card."""

    model_config = ConfigDict(populate_by_name=True)

    label: str
    value: str
    from_: str = Field(default="", alias="from")
    severity: ImpactSeverity = ImpactSeverity.NONE


class ChangeGroupSummaryResponse(BaseModel):
    """One change group as the Overview feed and Changes table render it."""

    id: str
    audit_id: str
    actor: str | None = None
    source: ChangeSource = ChangeSource.WEBHOOK
    occurred_at: datetime
    title: str
    summary: str
    object_count: int
    device_count: int
    affected_site_ids: list[str] = Field(default_factory=list)
    devices_label: str
    impact_severity: ImpactSeverity = ImpactSeverity.NONE
    recovery_state: RecoveryState = RecoveryState.NOT_APPLICABLE
    impact_label: str
    degraded_metrics: list[str] = Field(default_factory=list)
    metrics: list[ChangeMetricResponse] = Field(default_factory=list)
    monitoring_session_ids: list[str] = Field(default_factory=list)
    # False when the summary was built for a past instant, where impact and
    # recovery cannot be reported: the neutral values above then mean "not
    # shown", not "no impact".
    impact_known: bool = True
    impact_source: Literal["legacy"] | None = "legacy"
    shadow_impact: AuditImpactSummary | None = None
    is_mine: bool = False


class ChangeGroupDetailResponse(ChangeGroupSummaryResponse):
    """One change group with its evidence, objects, and competing changes."""

    message: str | None = None
    method: str | None = None
    baseline_confidence: BaselineConfidence = BaselineConfidence.NONE
    deterministic_assessment: str | None = None
    evidence: list[ChangeEvidenceResponse] = Field(default_factory=list)
    changed_objects: list[ChangedObjectResponse] = Field(default_factory=list)
    affected_devices: list[AffectedDeviceResponse] = Field(default_factory=list)
    competing_change_group_ids: list[str] = Field(default_factory=list)


class ChangeGroupListResponse(BaseModel):
    """One page of change groups and the total matching the query."""

    items: list[ChangeGroupSummaryResponse]
    total: int
