"""Two-person restore approval schemas."""

from datetime import datetime

from beanie import PydanticObjectId
from pydantic import BaseModel, Field

from mist_config_guardian_backend.models.approval import (
    ApprovalRule,
    ApprovalStatus,
    RestoreApproval,
)


class ApprovalCreateRequest(BaseModel):
    """The restore plan a second administrator is asked to review."""

    restore_operation_id: PydanticObjectId


class ApprovalDecisionRequest(BaseModel):
    """An optional reason recorded with an approval decision."""

    reason: str | None = Field(default=None, max_length=1000)


class TriggeredRuleResponse(BaseModel):
    """One policy rule with the evidence that triggered it."""

    rule: ApprovalRule
    detail: str


class ApprovalResponse(BaseModel):
    """An approval request as the restore page renders it."""

    id: str
    restore_operation_id: str
    status: ApprovalStatus
    triggered_rules: list[TriggeredRuleResponse]
    requested_by_email: str
    decided_by_email: str | None
    decided_at: datetime | None
    decision_reason: str | None
    expires_at: datetime | None
    plan_hash: str
    summary: str
    object_count: int
    delete_count: int
    created_at: datetime

    @classmethod
    def from_document(cls, approval: RestoreApproval) -> "ApprovalResponse":
        """Create an API response for one persisted approval request."""
        if approval.id is None:
            msg = "Persisted approval request is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(approval.id),
            restore_operation_id=str(approval.restore_operation_id),
            status=approval.status,
            triggered_rules=[
                TriggeredRuleResponse(rule=rule.rule, detail=rule.detail) for rule in approval.triggered_rules
            ],
            requested_by_email=approval.requested_by_email,
            decided_by_email=approval.decided_by_email,
            decided_at=approval.decided_at,
            decision_reason=approval.decision_reason,
            expires_at=approval.expires_at,
            plan_hash=approval.plan_hash,
            summary=approval.summary,
            object_count=approval.object_count,
            delete_count=approval.delete_count,
            created_at=approval.created_at,
        )


class ApprovalListResponse(BaseModel):
    """Paginated approval requests."""

    items: list[ApprovalResponse]
    total: int
