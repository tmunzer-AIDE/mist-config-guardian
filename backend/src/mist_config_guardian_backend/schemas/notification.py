"""In-application notification API schemas."""

from datetime import datetime

from pydantic import BaseModel

from mist_config_guardian_backend.models.notification import (
    Notification,
    NotificationKind,
    NotificationSeverity,
    NotificationTarget,
)


class NotificationResponse(BaseModel):
    """One notification as the browser feed renders it."""

    id: str
    kind: NotificationKind
    severity: NotificationSeverity
    title: str
    body: str
    target: NotificationTarget
    target_params: dict[str, str]
    mandatory: bool
    read: bool
    read_at: datetime | None
    created_at: datetime

    @classmethod
    def from_document(cls, notification: Notification) -> "NotificationResponse":
        """Convert a persisted notification into its API shape."""
        if notification.id is None:
            msg = "Persisted notification is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(notification.id),
            kind=notification.kind,
            severity=notification.severity,
            title=notification.title,
            body=notification.body,
            target=notification.target,
            target_params=dict(notification.target_params),
            mandatory=notification.mandatory,
            read=notification.read_at is not None,
            read_at=notification.read_at,
            created_at=notification.created_at,
        )


class NotificationListResponse(BaseModel):
    """Paginated notification feed with its unread badge count."""

    items: list[NotificationResponse]
    total: int
    unread: int


class NotificationUnreadCountResponse(BaseModel):
    """Unread badge count for one organization."""

    unread: int


class NotificationReadAllResponse(BaseModel):
    """Number of notifications marked read by a bulk acknowledgement."""

    updated: int
