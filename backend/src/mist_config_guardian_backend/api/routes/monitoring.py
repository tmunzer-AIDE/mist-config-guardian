"""Post-configuration impact monitoring endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_administrator,
)
from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringSession,
    MonitoringStatus,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.monitoring import (
    MonitoringSessionListResponse,
    MonitoringSessionResponse,
)
from mist_config_guardian_backend.services.organizations import (
    OrganizationNotFoundError,
    OrganizationService,
)

router = APIRouter(prefix="/organizations/{organization_id}/monitoring")


class MonitoringListFilters(BaseModel):
    """Monitoring list filters."""

    status: MonitoringStatus | None = None
    severity: ImpactSeverity | None = None
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


@router.get("")
async def list_monitoring_sessions(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
    filters: Annotated[MonitoringListFilters, Query()],
) -> MonitoringSessionListResponse:
    """List newest monitoring windows for one organization."""
    await _require_organization(organizations, organization_id)
    database_filters: dict[str, object] = {"organization_id": organization_id}
    if filters.status:
        database_filters["status"] = filters.status
    if filters.severity:
        database_filters["impact_severity"] = filters.severity
    query = MonitoringSession.find(database_filters)
    total = await query.count()
    sessions = await query.sort("-created_at").skip(filters.skip).limit(filters.limit).to_list()
    return MonitoringSessionListResponse(
        items=[MonitoringSessionResponse.from_document(item) for item in sessions],
        total=total,
    )


@router.get("/{session_id}")
async def get_monitoring_session(
    organization_id: PydanticObjectId,
    session_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> MonitoringSessionResponse:
    """Return one organization-scoped monitoring session."""
    await _require_organization(organizations, organization_id)
    session = await MonitoringSession.find_one(
        MonitoringSession.id == session_id,
        MonitoringSession.organization_id == organization_id,
    )
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring session not found",
        )
    return MonitoringSessionResponse.from_document(session)


async def _require_organization(
    organizations: OrganizationService,
    organization_id: PydanticObjectId,
) -> None:
    try:
        await organizations.get(organization_id)
    except OrganizationNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
