"""Organization overview aggregate API schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from mist_config_guardian_backend.schemas.change_group import ChangeGroupSummaryResponse


class OverviewCountsResponse(BaseModel):
    """Badge counts the shell polls for, independently of the feed."""

    change_groups: int = 0
    impacting: int = 0
    mine: int = 0
    unrecovered: int = 0
    pending_approvals: int = 0
    failed_restores: int = 0


class SafetyNetItemResponse(BaseModel):
    """One line of the Overview safety-net card."""

    key: Literal["backup", "webhook", "reconciliation", "credential"]
    label: str
    status: Literal["ok", "warn", "crit"]
    detail: str


class PendingApprovalResponse(BaseModel):
    """One restore plan waiting for a second pair of eyes."""

    id: str
    restore_operation_id: str
    title: str
    detail: str
    requested_by_email: str
    requested_at: datetime


class FailedRestoreResponse(BaseModel):
    """One restore that stopped part way and may need compensation."""

    id: str
    title: str
    detail: str
    failed_at: datetime
    compensation_available: bool = False


class OrganizationOverviewResponse(BaseModel):
    """Everything the Overview page renders, in one purpose-built read model."""

    generated_at: datetime
    range_start: datetime
    range_end: datetime
    counts: OverviewCountsResponse
    change_groups: list[ChangeGroupSummaryResponse] = Field(default_factory=list)
    safety_net: list[SafetyNetItemResponse] = Field(default_factory=list)
    pending_approvals: list[PendingApprovalResponse] = Field(default_factory=list)
    failed_restores: list[FailedRestoreResponse] = Field(default_factory=list)
    latest_snapshot_at: datetime | None = None
    latest_snapshot_objects: int | None = None
    # True when built as of a past instant. The feed and its counts are then
    # historical; the operational sections have no past and are left empty.
    historical: bool = False
