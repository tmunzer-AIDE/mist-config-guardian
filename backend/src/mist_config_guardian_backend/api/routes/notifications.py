"""In-application notification endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from mist_config_guardian_backend.api.dependencies import require_organization, require_viewer
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.notification import (
    NotificationListResponse,
    NotificationReadAllResponse,
    NotificationResponse,
    NotificationUnreadCountResponse,
)
from mist_config_guardian_backend.services.notifications import NotificationService

router = APIRouter(prefix="/organizations/{organization_id}/notifications")


def get_notification_service() -> NotificationService:
    """Build the in-application notification service."""
    return NotificationService()


class NotificationListFilters(BaseModel):
    """Notification feed filters."""

    unread_only: bool = False
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=50, ge=1, le=200)


def _identifier(document: Organization | User) -> PydanticObjectId:
    if document.id is None:
        msg = "Persisted document is missing an identifier"
        raise ValueError(msg)
    return document.id


@router.get("")
async def list_notifications(
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    notifications: Annotated[NotificationService, Depends(get_notification_service)],
    filters: Annotated[NotificationListFilters, Query()],
) -> NotificationListResponse:
    """List notifications visible to the caller, newest first."""
    organization_id = _identifier(organization)
    user_id = _identifier(viewer)
    items, total = await notifications.list_for(
        organization_id,
        user_id,
        unread_only=filters.unread_only,
        skip=filters.skip,
        limit=filters.limit,
    )
    unread = await notifications.unread_count(organization_id, user_id)
    return NotificationListResponse(
        items=[NotificationResponse.from_document(item) for item in items],
        total=total,
        unread=unread,
    )


@router.get("/unread-count")
async def count_unread_notifications(
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    notifications: Annotated[NotificationService, Depends(get_notification_service)],
) -> NotificationUnreadCountResponse:
    """Return the unread badge count for the caller."""
    unread = await notifications.unread_count(_identifier(organization), _identifier(viewer))
    return NotificationUnreadCountResponse(unread=unread)


@router.post("/read-all")
async def mark_all_notifications_read(
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    notifications: Annotated[NotificationService, Depends(get_notification_service)],
) -> NotificationReadAllResponse:
    """Mark every notification visible to the caller as read."""
    updated = await notifications.mark_all_read(_identifier(organization), _identifier(viewer))
    return NotificationReadAllResponse(updated=updated)


@router.post("/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notification_read(
    notification_id: PydanticObjectId,
    organization: Annotated[Organization, Depends(require_organization)],
    viewer: Annotated[User, Depends(require_viewer)],
    notifications: Annotated[NotificationService, Depends(get_notification_service)],
) -> None:
    """Mark one notification read, or fail when the caller cannot see it."""
    marked = await notifications.mark_read(
        _identifier(organization),
        _identifier(viewer),
        notification_id,
    )
    if not marked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found",
        )
