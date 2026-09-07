"""Dependency-aware restore planning endpoints."""

from typing import Annotated
from uuid import uuid4

from beanie import PydanticObjectId
from celery.exceptions import CeleryError
from fastapi import APIRouter, Depends, HTTPException, Query, status
from kombu.exceptions import OperationalError

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    get_restore_authorization_service,
    require_administrator,
)
from mist_config_guardian_backend.integrations.mist import MistVerificationError
from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.restore import (
    RestoreExecuteRequest,
    RestoreOperationListResponse,
    RestoreOperationResponse,
    RestorePlanRequest,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationNotFoundError,
    OrganizationService,
)
from mist_config_guardian_backend.services.restore_authorization import (
    RestoreAuthorizationError,
    RestoreAuthorizationService,
)
from mist_config_guardian_backend.services.restore_planner import (
    RestorePlanner,
    RestorePlanningError,
)
from mist_config_guardian_backend.worker import celery_app

router = APIRouter(prefix="/organizations/{organization_id}/restores")


@router.post("/plans", status_code=status.HTTP_201_CREATED)
async def create_restore_plan(
    organization_id: PydanticObjectId,
    request: RestorePlanRequest,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    administrator: Annotated[User, Depends(require_administrator)],
) -> RestoreOperationResponse:
    """Create a side-effect-free dependency-aware restore plan."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if administrator.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authenticated administrator is missing an identifier",
        )
    try:
        operation = await RestorePlanner().create_plan(
            organization_id=organization_id,
            requested_by=administrator.id,
            version_ids=request.version_ids,
            mode=request.mode,
            include_dependencies=request.include_dependencies,
        )
    except RestorePlanningError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return RestoreOperationResponse.from_document(operation)


@router.post("/{operation_id}/execute", status_code=status.HTTP_202_ACCEPTED)
async def execute_restore(
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    request: RestoreExecuteRequest,
    authorization: Annotated[
        RestoreAuthorizationService,
        Depends(get_restore_authorization_service),
    ],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> RestoreOperationResponse:
    """Verify a fresh Mist administrator and queue the reviewed plan."""
    task_id = str(uuid4())
    try:
        operation = await authorization.authorize(
            organization_id,
            operation_id,
            request.administrator_token.get_secret_value(),
            task_id,
        )
    except (RestoreAuthorizationError, MistVerificationError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    if operation.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authorized restore is missing an identifier",
        )
    try:
        celery_app.send_task(
            "restores.execute",
            args=[str(operation.id)],
            task_id=task_id,
        )
    except (CeleryError, OperationalError) as exc:
        await authorization.release(operation.id, task_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Restore worker queue is unavailable",
        ) from exc
    return RestoreOperationResponse.from_document(operation)


@router.get("")
async def list_restore_operations(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> RestoreOperationListResponse:
    """List restore operations newest first."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    query = RestoreOperation.find(RestoreOperation.organization_id == organization_id)
    total = await query.count()
    operations = await query.sort("-created_at").skip(skip).limit(limit).to_list()
    return RestoreOperationListResponse(
        items=[RestoreOperationResponse.from_document(item) for item in operations],
        total=total,
    )


@router.get("/{operation_id}")
async def get_restore_operation(
    organization_id: PydanticObjectId,
    operation_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> RestoreOperationResponse:
    """Return one restore operation."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    operation = await RestoreOperation.find_one(
        RestoreOperation.id == operation_id,
        RestoreOperation.organization_id == organization_id,
    )
    if operation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Restore not found")
    return RestoreOperationResponse.from_document(operation)
