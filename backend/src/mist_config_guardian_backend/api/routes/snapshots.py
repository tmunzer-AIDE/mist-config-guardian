"""Configuration snapshot endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from celery.exceptions import CeleryError
from fastapi import APIRouter, Depends, HTTPException, Query, status
from kombu.exceptions import OperationalError
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_operator,
    require_viewer,
)
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.snapshot import (
    SnapshotError,
    SnapshotManifest,
    SnapshotStatus,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.snapshot import (
    SnapshotManifestListResponse,
    SnapshotManifestResponse,
    SnapshotTaskResponse,
    SnapshotTriggerRequest,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationNotFoundError,
    OrganizationService,
)
from mist_config_guardian_backend.worker import celery_app

router = APIRouter(prefix="/organizations/{organization_id}/snapshots")


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def trigger_snapshot(
    organization_id: PydanticObjectId,
    request: SnapshotTriggerRequest,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _operator: Annotated[User, Depends(require_operator)],
) -> SnapshotTaskResponse:
    """Queue a snapshot unless one is already active."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    manifest = SnapshotManifest(
        organization_id=organization_id,
        kind=request.kind,
        status=SnapshotStatus.PENDING,
    )
    try:
        await manifest.insert()
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A snapshot is already in progress",
        ) from exc
    if manifest.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Snapshot request could not be persisted",
        )

    try:
        task = celery_app.send_task(
            "snapshots.collect",
            args=[str(organization_id), request.kind, str(manifest.id)],
        )
    except (CeleryError, OperationalError) as exc:
        manifest.status = SnapshotStatus.FAILED
        manifest.active = False
        manifest.completed_at = utc_now()
        manifest.errors = [
            SnapshotError(
                object_type="task",
                message="Snapshot worker queue is unavailable",
                retryable=True,
            )
        ]
        manifest.touch()
        await manifest.save()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Snapshot worker queue is unavailable",
        ) from exc
    return SnapshotTaskResponse(task_id=task.id)


@router.get("")
async def list_snapshots(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> SnapshotManifestListResponse:
    """List snapshot history newest first."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    query = SnapshotManifest.find(SnapshotManifest.organization_id == organization_id)
    total = await query.count()
    manifests = await query.sort("-created_at").skip(skip).limit(limit).to_list()
    return SnapshotManifestListResponse(
        items=[SnapshotManifestResponse.from_document(item) for item in manifests],
        total=total,
    )
