"""Point-in-time navigation and state reconstruction endpoints."""

from datetime import datetime
from typing import Annotated, Literal

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from mist_config_guardian_backend.api.dependencies import require_organization
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.schemas.history import ObjectVersionResponse
from mist_config_guardian_backend.schemas.point_in_time import (
    PointInTimeModeResponse,
    PointInTimeStateResponse,
    TimelineMarkerListResponse,
)
from mist_config_guardian_backend.services.change_groups import as_utc
from mist_config_guardian_backend.services.point_in_time import PointInTimeService

router = APIRouter(prefix="/organizations/{organization_id}/point-in-time")

AsOfHeader = Annotated[datetime | None, Header(alias="X-Config-Guardian-As-Of")]


def get_point_in_time_service() -> PointInTimeService:
    """Build the point-in-time navigation service."""
    return PointInTimeService()


def _identifier(organization: Organization) -> PydanticObjectId:
    if organization.id is None:
        msg = "Persisted organization is missing an identifier"
        raise ValueError(msg)
    return organization.id


@router.get("/markers")
async def list_markers(
    organization: Annotated[Organization, Depends(require_organization)],
    service: Annotated[PointInTimeService, Depends(get_point_in_time_service)],
    range: Annotated[Literal["24h", "7d", "30d"], Query()] = "24h",  # noqa: A002 - the wire name is fixed
    as_of: AsOfHeader = None,
) -> TimelineMarkerListResponse:
    """List the change markers drawn on the shell's time bar."""
    return await service.markers(_identifier(organization), range_key=range, as_of=as_of)


@router.get("/mode")
async def read_mode(
    _organization: Annotated[Organization, Depends(require_organization)],
    as_of: AsOfHeader = None,
) -> PointInTimeModeResponse:
    """Report whether this request is browsing a reconstructed past instant."""
    return PointInTimeModeResponse(
        historical=as_of is not None,
        as_of=as_utc(as_of) if as_of is not None else None,
    )


@router.get("/state")
async def read_state(
    organization: Annotated[Organization, Depends(require_organization)],
    service: Annotated[PointInTimeService, Depends(get_point_in_time_service)],
    at: Annotated[datetime, Query()],
    scope: Annotated[Literal["org", "site"], Query()] = "org",
    site_id: Annotated[str | None, Query()] = None,
) -> PointInTimeStateResponse:
    """Reconstruct an organization or site as it existed at an instant."""
    if scope == "site" and not site_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="site_id is required when scope is site",
        )
    return await service.state_at(
        _identifier(organization),
        at=at,
        scope=scope,
        site_id=site_id,
    )


@router.get("/objects/{logical_object_id}")
async def read_object_at(
    logical_object_id: PydanticObjectId,
    organization: Annotated[Organization, Depends(require_organization)],
    service: Annotated[PointInTimeService, Depends(get_point_in_time_service)],
    at: Annotated[datetime | None, Query()] = None,
    as_of: AsOfHeader = None,
) -> ObjectVersionResponse:
    """Return one object's configuration as it existed at an instant."""
    instant = at or as_of
    version = await service.object_at(
        _identifier(organization),
        logical_object_id,
        instant if instant is not None else utc_now(),
    )
    if version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Object did not exist at the requested instant",
        )
    return ObjectVersionResponse.from_document(version)
