"""Post-configuration impact monitoring endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import (
    get_organization_service,
    require_viewer,
)
from mist_config_guardian_backend.models.monitoring import (
    ImpactSeverity,
    MonitoringSession,
    MonitoringStatus,
)
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.schemas.monitoring import (
    MonitoringChangeRef,
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
    audit_id: str | None = None


@router.get("")
async def list_monitoring_sessions(
    organization_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
    filters: Annotated[MonitoringListFilters, Query()],
) -> MonitoringSessionListResponse:
    """List newest monitoring windows for one organization."""
    await _require_organization(organizations, organization_id)
    database_filters: dict[str, object] = {"organization_id": organization_id}
    if filters.status:
        database_filters["status"] = filters.status
    if filters.severity:
        database_filters["impact_severity"] = filters.severity
    if filters.audit_id:
        database_filters["audit_ids"] = filters.audit_id
    query = MonitoringSession.find(database_filters)
    total = await query.count()
    sessions = await query.sort("-created_at").skip(filters.skip).limit(filters.limit).to_list()
    changes = await _change_refs(organization_id, sessions)
    return MonitoringSessionListResponse(
        items=[
            MonitoringSessionResponse.from_document(item, [changes[a] for a in item.audit_ids if a in changes])
            for item in sessions
        ],
        total=total,
    )


@router.get("/{session_id}")
async def get_monitoring_session(
    organization_id: PydanticObjectId,
    session_id: PydanticObjectId,
    organizations: Annotated[OrganizationService, Depends(get_organization_service)],
    _viewer: Annotated[User, Depends(require_viewer)],
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
    changes = await _change_refs(organization_id, [session])
    return MonitoringSessionResponse.from_document(session, [changes[a] for a in session.audit_ids if a in changes])


async def _change_refs(
    organization_id: PydanticObjectId, sessions: list[MonitoringSession]
) -> dict[str, MonitoringChangeRef]:
    audit_ids = sorted({audit for session in sessions for audit in session.audit_ids})
    if not audit_ids:
        return {}
    groups = await AuditChangeGroup.find({"organization_id": organization_id, "audit_id": {"$in": audit_ids}}).to_list()
    return {
        group.audit_id: MonitoringChangeRef(
            id=str(group.id),
            audit_id=group.audit_id,
            title=group.summary or group.message or f"Configuration change {group.audit_id}",
            occurred_at=group.occurred_at,
        )
        for group in groups
    }


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
