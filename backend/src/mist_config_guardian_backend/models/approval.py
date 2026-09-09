"""Two-person approval persistence for restore plans."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class ApprovalStatus(StrEnum):
    """Approval request lifecycle."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


class ApprovalRule(StrEnum):
    """Policy rule that made a plan require approval."""

    ORGANIZATION_SCOPE = "organization_scope"
    EXACT_MODE_DELETES = "exact_mode_deletes"
    OBJECT_COUNT_THRESHOLD = "object_count_threshold"
    SENSITIVE_OBJECT_TYPE = "sensitive_object_type"


class TriggeredRule(BaseModel):
    """One policy rule with the evidence that triggered it."""

    rule: ApprovalRule
    detail: str


class ApprovalPolicy(BaseModel):
    """Per-organization approval thresholds."""

    enabled: bool = False
    require_for_organization_scope: bool = True
    require_for_exact_deletes: bool = True
    object_count_threshold: int | None = Field(default=25, ge=1)
    sensitive_object_types: list[str] = Field(default_factory=list)
    expiry_hours: int = Field(default=24, ge=1, le=168)


class RestoreApproval(TimestampedModel, Document):
    """An approval request bound to an immutable restore plan hash."""

    organization_id: PydanticObjectId
    restore_operation_id: PydanticObjectId
    requested_by: PydanticObjectId
    requested_by_email: str
    plan_hash: str
    triggered_rules: list[TriggeredRule] = Field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: PydanticObjectId | None = None
    decided_by_email: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    expires_at: datetime
    summary: str = ""
    object_count: int = 0
    delete_count: int = 0

    class Settings:
        name = "restore_approvals"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("restore_operation_id", 1)],
                unique=True,
                name="restore_approval_operation_unique",
            ),
            IndexModel([("organization_id", 1), ("status", 1), ("created_at", -1)]),
        ]
