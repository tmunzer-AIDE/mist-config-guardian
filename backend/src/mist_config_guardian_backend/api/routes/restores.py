"""Restore planning, approval-gated execution, compensation, and verification."""

from typing import Annotated
from uuid import uuid4

from beanie import PydanticObjectId
from celery.exceptions import CeleryError
from fastapi import APIRouter, Depends, HTTPException, Query, status
from kombu.exceptions import OperationalError

from mist_config_guardian_backend.api.dependencies import (
    get_credential_vault,
    get_restore_authorization_service,
    require_administrator,
    require_operator,
    require_organization,
)
from mist_config_guardian_backend.api.routes.approvals import get_approval_service
from mist_config_guardian_backend.integrations.mist import MistVerificationError
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.approval import ApprovalResponse
from mist_config_guardian_backend.schemas.mist_login import MistLoginCredentials
from mist_config_guardian_backend.schemas.restore import (
    RestoreExecuteRequest,
    RestoreOperationListResponse,
    RestoreOperationResponse,
    RestorePlanRequest,
    RestoreTargetListResponse,
    RestoreVerificationResponse,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import (
    ApprovalError,
    ApprovalService,
    organization_policy,
)
from mist_config_guardian_backend.services.mfa import require_fresh_mfa
from mist_config_guardian_backend.services.restore_authorization import (
    RestoreAuthorizationError,
    RestoreAuthorizationService,
)
from mist_config_guardian_backend.services.restore_compensation import (
    RestoreCompensationError,
    RestoreCompensationService,
)
from mist_config_guardian_backend.services.restore_planner import (
    RestorePlanner,
    RestorePlanningError,
    RestorePlanRepository,
    RestoreStateStore,
    assert_plan_current,
    get_restore_plan_repository,
    get_restore_state_store,
)
from mist_config_guardian_backend.services.restore_targets import (
    RestoreTargetQuery,
    RestoreTargetService,
    TargetScope,
)
from mist_config_guardian_backend.services.restore_verification import RestoreVerificationService
from mist_config_guardian_backend.worker import celery_app

router = APIRouter(prefix="/organizations/{organization_id}/restores")


def get_plan_state_store() -> RestoreStateStore:
    """Build the restore plan-state store."""
    return get_restore_state_store()


def get_restore_plans() -> RestorePlanRepository:
    """Build the organization-scoped restore plan repository."""
    return get_restore_plan_repository()


def get_restore_target_service() -> RestoreTargetService:
    """Build the restorable object discovery service."""
    return RestoreTargetService()


def get_restore_compensation_service() -> RestoreCompensationService:
    """Build the compensating-plan service."""
    return RestoreCompensationService()


def get_restore_verification_service() -> RestoreVerificationService:
    """Build the post-restore verification service."""
    return RestoreVerificationService()


@router.post("/plans", status_code=status.HTTP_201_CREATED)
async def create_restore_plan(  # noqa: PLR0913, PLR0917 - each argument is a separate injected dependency
    organization_id: PydanticObjectId,
    request: RestorePlanRequest,
    organization: Annotated[Organization, Depends(require_organization)],
    store: Annotated[RestoreStateStore, Depends(get_plan_state_store)],
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
    operator: Annotated[User, Depends(require_operator)],
) -> RestoreOperationResponse:
    """Create a side-effect-free dependency-aware restore plan."""
    if operator.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authenticated operator is missing an identifier",
        )
    try:
        operation = await RestorePlanner(store, organization_policy(organization), vault).create_plan(
            organization_id=organization_id,
            requested_by=operator.id,
            version_ids=request.version_ids,
            mode=request.mode,
            include_dependencies=request.include_dependencies,
        )
    except RestorePlanningError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return RestoreOperationResponse.from_document(operation)


@router.get("/targets")
async def list_restore_targets(  # noqa: PLR0913, PLR0917 - filters and pagination are separate query parameters
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    targets: Annotated[RestoreTargetService, Depends(get_restore_target_service)],
    _operator: Annotated[User, Depends(require_operator)],
    scope: TargetScope = "all",
    site_id: str | None = None,
    object_type: str | None = None,
    q: str | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> RestoreTargetListResponse:
    """List restorable objects with the facet counts the filters render."""
    page = await targets.search(
        RestoreTargetQuery(
            organization_id=organization_id,
            scope=scope,
            site_id=site_id,
            object_type=object_type,
            q=q,
            skip=skip,
            limit=limit,
        )
    )
    return RestoreTargetListResponse.from_page(page)


@router.get("")
async def list_restore_operations(
    organization_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    _operator: Annotated[User, Depends(require_operator)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> RestoreOperationListResponse:
    """List restore operations newest first."""
    operations, total = await plans.page(organization_id, skip=skip, limit=limit)
    return RestoreOperationListResponse(
        items=[await _operation_response(item, approvals) for item in operations],
        total=total,
    )


@router.get("/{operation_id}")
async def get_restore_operation(
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    _operator: Annotated[User, Depends(require_operator)],
) -> RestoreOperationResponse:
    """Return one restore operation, including live per-action progress."""
    operation = await _load(plans, organization_id, operation_id)
    return await _operation_response(operation, approvals)


@router.get("/{operation_id}/verification")
async def get_restore_verification(
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    verification: Annotated[RestoreVerificationService, Depends(get_restore_verification_service)],
    _operator: Annotated[User, Depends(require_operator)],
) -> RestoreVerificationResponse:
    """Return the post-restore checks recorded for one operation."""
    operation = await _load(plans, organization_id, operation_id)
    return RestoreVerificationResponse.from_result(await verification.result_for(operation))


@router.post("/{operation_id}/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_restore(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    request: RestoreExecuteRequest,
    organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    authorization: Annotated[RestoreAuthorizationService, Depends(get_restore_authorization_service)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    store: Annotated[RestoreStateStore, Depends(get_plan_state_store)],
    _administrator: Annotated[User, Depends(require_administrator)],
    _stepped_up: Annotated[User, Depends(require_fresh_mfa)],
) -> RestoreOperationResponse:
    """Verify a fresh Mist administrator and queue the reviewed plan."""
    operation = await _load(plans, organization_id, operation_id)
    await _assert_plan_current(store, operation)
    await _assert_approved(organization, operation, approvals)
    return await _authorize_and_queue(
        organization_id,
        operation,
        authorization,
        approvals,
        request.credential(),
    )


@router.post("/{operation_id}/compensation", status_code=status.HTTP_201_CREATED)
async def create_compensation_plan(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    _organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    compensation: Annotated[RestoreCompensationService, Depends(get_restore_compensation_service)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    administrator: Annotated[User, Depends(require_administrator)],
) -> RestoreOperationResponse:
    """Plan the reversal of every action a failed restore actually applied."""
    operation = await _load(plans, organization_id, operation_id)
    if administrator.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authenticated administrator is missing an identifier",
        )
    try:
        plan = await compensation.create_compensation_plan(
            operation=operation,
            requested_by=administrator.id,
        )
    except RestoreCompensationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _operation_response(plan, approvals, compensation_available=False)


@router.post("/{operation_id}/compensation/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_compensation_plan(  # noqa: PLR0913, PLR0917 - one dependency per collaborating service
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    request: RestoreExecuteRequest,
    organization: Annotated[Organization, Depends(require_organization)],
    plans: Annotated[RestorePlanRepository, Depends(get_restore_plans)],
    authorization: Annotated[RestoreAuthorizationService, Depends(get_restore_authorization_service)],
    compensation: Annotated[RestoreCompensationService, Depends(get_restore_compensation_service)],
    approvals: Annotated[ApprovalService, Depends(get_approval_service)],
    store: Annotated[RestoreStateStore, Depends(get_plan_state_store)],
    _administrator: Annotated[User, Depends(require_administrator)],
    _stepped_up: Annotated[User, Depends(require_fresh_mfa)],
) -> RestoreOperationResponse:
    """Verify a fresh Mist administrator and queue the compensating plan.

    Compensation writes with the same delegated administrator identity a
    restore does; it never falls back to the read-only service token.
    """
    operation = await _load(plans, organization_id, operation_id)
    plan = await compensation.compensation_for(operation)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No compensating plan has been created for this restore",
        )
    await _assert_plan_current(store, plan)
    # Compensation writes to Mist with the same authority a restore does, and
    # undoes objects the same way, so it clears the same approval policy. The
    # ordinary execute route enforced it and this one did not, which let one
    # administrator run a destructive plan the policy says needs two.
    await _assert_approved(organization, plan, approvals)
    return await _authorize_and_queue(
        organization_id,
        plan,
        authorization,
        approvals,
        request.credential(),
    )


async def _load(
    plans: RestorePlanRepository,
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
) -> RestoreOperation:
    """Load one organization-scoped restore operation, or fail with 404."""
    operation = await plans.load(organization_id, operation_id)
    if operation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Restore not found")
    return operation


async def _operation_response(
    operation: RestoreOperation,
    approvals: ApprovalService,
    *,
    compensation_available: bool | None = None,
) -> RestoreOperationResponse:
    """Render one operation with its approval and compensation availability."""
    approval = await approvals.for_operation(operation)
    return RestoreOperationResponse.from_document(
        operation,
        approval=None if approval is None else ApprovalResponse.from_document(approval),
        compensation_available=(
            operation.status is RestoreStatus.COMPENSATION_AVAILABLE
            if compensation_available is None
            else compensation_available
        ),
    )


async def _assert_plan_current(
    store: RestoreStateStore,
    operation: RestoreOperation,
) -> None:
    """Refuse execution of a plan that no longer hashes as it was reviewed."""
    try:
        await assert_plan_current(store, operation)
    except RestorePlanningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


async def _assert_approved(
    organization: Organization,
    operation: RestoreOperation,
    approvals: ApprovalService,
) -> None:
    """Refuse execution while a policy-required approval is not in force."""
    try:
        await approvals.assert_execution_allowed(organization, operation)
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


async def _authorize_and_queue(
    organization_id: PydanticObjectId,
    operation: RestoreOperation,
    authorization: RestoreAuthorizationService,
    approvals: ApprovalService,
    credential: str | MistLoginCredentials,
) -> RestoreOperationResponse:
    """Reserve the plan with a delegated credential and hand it to the worker."""
    if operation.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorized restore is missing an identifier",
        )
    task_id = str(uuid4())
    try:
        reserved = await authorization.authorize(
            organization_id,
            operation.id,
            credential,
            task_id,
        )
    except (RestoreAuthorizationError, MistVerificationError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    if reserved.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorized restore is missing an identifier",
        )
    try:
        celery_app.send_task("restores.execute", args=[str(reserved.id)], task_id=task_id)
    except (CeleryError, OperationalError) as exc:
        await authorization.release(reserved.id, task_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Restore worker queue is unavailable",
        ) from exc
    return await _operation_response(reserved, approvals)
