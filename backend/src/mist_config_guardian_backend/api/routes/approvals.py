"""Two-person restore approval endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status

from mist_config_guardian_backend.api.dependencies import (
    require_administrator,
    require_operator,
    require_organization,
    require_viewer,
)
from mist_config_guardian_backend.models.approval import ApprovalStatus
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.approval import (
    ApprovalCreateRequest,
    ApprovalDecisionRequest,
    ApprovalListResponse,
    ApprovalResponse,
)
from mist_config_guardian_backend.services.approvals import (
    ApprovalError,
    ApprovalService,
    SelfApprovalError,
)

router = APIRouter(prefix="/organizations/{organization_id}/approvals")


def get_approval_service() -> ApprovalService:
    """Build the two-person restore approval service."""
    return ApprovalService()


@router.post("", status_code=status.HTTP_201_CREATED)
async def request_approval(
    organization_id: PydanticObjectId,
    request: ApprovalCreateRequest,
    organization: Annotated[Organization, Depends(require_organization)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    operator: Annotated[User, Depends(require_operator)],
) -> ApprovalResponse:
    """Ask a second administrator to review one restore plan."""
    operation = await approvals.load_plan(organization_id, request.restore_operation_id)
    if operation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Restore not found")
    try:
        approval = await approvals.request(organization, operation, operator)
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return ApprovalResponse.from_document(approval)


@router.get("")
async def list_approvals(
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    approval_status: Annotated[ApprovalStatus | None, Query(alias="status")] = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> ApprovalListResponse:
    """List approval requests newest first, optionally filtered by status."""
    items, total = await approvals.list(
        organization_id,
        status=approval_status,
        skip=skip,
        limit=limit,
    )
    return ApprovalListResponse(
        items=[ApprovalResponse.from_document(item) for item in items],
        total=total,
    )


@router.get("/{approval_id}")
async def get_approval(
    organization_id: PydanticObjectId,
    approval_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
) -> ApprovalResponse:
    """Return one approval request with a freshly reconciled status."""
    approval = await approvals.get(organization_id, approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found")
    return ApprovalResponse.from_document(approval)


@router.post("/{approval_id}/approve")
async def approve_restore(
    organization_id: PydanticObjectId,
    approval_id: PydanticObjectId,
    request: ApprovalDecisionRequest,
    _organization: Annotated[Organization, Depends(require_organization)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    administrator: Annotated[User, Depends(require_administrator)],
) -> ApprovalResponse:
    """Approve one restore plan as a second administrator."""
    return await _decide(
        approvals,
        organization_id,
        approval_id,
        administrator,
        approved=True,
        reason=request.reason,
    )


@router.post("/{approval_id}/reject")
async def reject_restore(
    organization_id: PydanticObjectId,
    approval_id: PydanticObjectId,
    request: ApprovalDecisionRequest,
    _organization: Annotated[Organization, Depends(require_organization)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    administrator: Annotated[User, Depends(require_administrator)],
) -> ApprovalResponse:
    """Reject one restore plan as a second administrator."""
    return await _decide(
        approvals,
        organization_id,
        approval_id,
        administrator,
        approved=False,
        reason=request.reason,
    )


async def _decide(  # noqa: PLR0913 - one argument per recorded decision field
    approvals: ApprovalService,
    organization_id: PydanticObjectId,
    approval_id: PydanticObjectId,
    administrator: User,
    *,
    approved: bool,
    reason: str | None,
) -> ApprovalResponse:
    """Record one decision, refusing self-approval with a conflict."""
    try:
        approval = await approvals.decide(
            organization_id,
            approval_id,
            administrator,
            approved=approved,
            reason=reason,
        )
    except SelfApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ApprovalError as exc:
        detail = str(exc)
        code = status.HTTP_404_NOT_FOUND if detail == "Approval request not found" else status.HTTP_409_CONFLICT
        raise HTTPException(status_code=code, detail=detail) from exc
    return ApprovalResponse.from_document(approval)
