"""Configuration object and immutable version history endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_administrator,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.history import (
    LogicalObjectListResponse,
    LogicalObjectResponse,
    ObjectVersionListResponse,
    ObjectVersionResponse,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationNotFoundError,
    OrganizationService,
)

router = APIRouter(prefix="/organizations/{organization_id}/objects")


class ObjectListFilters(BaseModel):
    """Configuration history list filters."""

    object_type: str | None = None
    site_id: str | None = None
    include_deleted: bool = False
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


@router.get("")
async def list_objects(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
    filters: Annotated[ObjectListFilters, Query()],
) -> LogicalObjectListResponse:
    """List stable objects with optional type, site, and deletion filters."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    database_filters: dict[str, object] = {"organization_id": organization_id}
    if filters.object_type:
        database_filters["object_type"] = filters.object_type
    if filters.site_id:
        database_filters["site_mist_id"] = filters.site_id
    if not filters.include_deleted:
        database_filters["is_deleted"] = False
    query = LogicalObject.find(database_filters)
    total = await query.count()
    objects = await query.sort("object_type", "name").skip(filters.skip).limit(filters.limit).to_list()
    return LogicalObjectListResponse(
        items=[LogicalObjectResponse.from_document(item) for item in objects],
        total=total,
    )


@router.get("/{logical_object_id}/versions")
async def list_object_versions(
    organization_id: PydanticObjectId,
    logical_object_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> ObjectVersionListResponse:
    """Return an object's immutable timeline newest first."""
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    logical = await LogicalObject.find_one(
        LogicalObject.id == logical_object_id,
        LogicalObject.organization_id == organization_id,
    )
    if logical is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found")
    versions = (
        await ObjectVersion.find(
            ObjectVersion.organization_id == organization_id,
            ObjectVersion.logical_object_id == logical_object_id,
        )
        .sort("-version")
        .to_list()
    )
    return ObjectVersionListResponse(
        items=[ObjectVersionResponse.from_document(item) for item in versions],
        total=len(versions),
    )
