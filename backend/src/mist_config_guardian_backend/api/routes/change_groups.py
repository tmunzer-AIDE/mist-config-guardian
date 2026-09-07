"""Administrator change-group read endpoints."""

from datetime import datetime
from typing import Annotated, Literal

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import require_organization, require_viewer
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.change_group import (
    ChangeGroupDetailResponse,
    ChangeGroupListResponse,
)
from mist_config_guardian_backend.services.change_groups import (
    ChangeGroupFilters,
    ChangeGroupService,
)

router = APIRouter(prefix="/organizations/{organization_id}/change-groups")


def get_change_group_service() -> ChangeGroupService:
    """Build the change-group read model."""
    return ChangeGroupService()


class ChangeGroupListFilters(BaseModel):
    """Filters the Changes table and the search page send."""

    range: Literal["24h", "7d", "30d"] = "24h"
    severity: Literal["any", "critical", "warning", "none"] = "any"
    actor: str | None = None
    q: str | None = None
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)
    as_of: datetime | None = None


def _identifier(organization: Organization) -> PydanticObjectId:
    if organization.id is None:
        msg = "Persisted organization is missing an identifier"
        raise ValueError(msg)
    return organization.id


@router.get("")
async def list_change_groups(
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    service: Annotated[ChangeGroupService, Depends(get_change_group_service)],
    filters: Annotated[ChangeGroupListFilters, Query()],
) -> ChangeGroupListResponse:
    """List change groups in the selected window, newest first."""
    items, total = await service.list_groups(
        _identifier(organization),
        ChangeGroupFilters(
            range_key=filters.range,
            severity=filters.severity,
            actor=filters.actor,
            query=filters.q,
            skip=filters.skip,
            limit=filters.limit,
            as_of=filters.as_of,
        ),
        viewer_email=viewer.email,
    )
    return ChangeGroupListResponse(items=items, total=total)


@router.get("/{change_group_id}")
async def read_change_group(
    change_group_id: PydanticObjectId,
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    service: Annotated[ChangeGroupService, Depends(get_change_group_service)],
) -> ChangeGroupDetailResponse:
    """Return one change group with its objects, devices, and evidence."""
    detail = await service.get_group(
        _identifier(organization),
        change_group_id,
        viewer_email=viewer.email,
    )
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Change group not found")
    return detail
