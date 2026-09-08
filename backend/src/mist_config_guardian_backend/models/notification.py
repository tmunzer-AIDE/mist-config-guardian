"""In-application notification persistence."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class NotificationKind(StrEnum):
    """Notification category shown as the feed tag."""

    CRITICAL = "critical"
    RESTORE = "restore"
    WEBHOOK = "webhook"
    APPROVAL = "approval"
    SNAPSHOT = "snapshot"
    CREDENTIAL = "credential"
    RECONCILIATION = "reconciliation"


class NotificationSeverity(StrEnum):
    """Severity that drives the notification's tone."""

    CRITICAL = "crit"
    WARNING = "warn"
    INFO = "info"
    OK = "ok"


class NotificationTarget(StrEnum):
    """Application page a notification deep-links into."""

    OVERVIEW = "overview"
    CHANGES = "changes"
    HISTORY = "history"
    RESTORE = "restore"
    IMPACT = "impact"
    SETTINGS = "settings"


class NotificationReadReceipt(BaseModel):
    """One member's acknowledgement of a notification."""

    user_id: PydanticObjectId
    read_at: datetime


class Notification(TimestampedModel, Document):
    """One notification, organization-wide or addressed to one recipient.

    Read state is kept per member rather than on the document, because an
    organization-wide alert is one document seen by everyone: a single
    ``read_at`` would let the first person to open it clear it for the rest.
    """

    organization_id: PydanticObjectId
    user_id: PydanticObjectId | None = None
    kind: NotificationKind
    severity: NotificationSeverity
    title: str
    body: str = ""
    target: NotificationTarget = NotificationTarget.OVERVIEW
    target_params: dict[str, str] = Field(default_factory=dict)
    mandatory: bool = False
    read_by: list[NotificationReadReceipt] = Field(default_factory=list)
    dedupe_key: str | None = None

    def read_at_for(self, user_id: PydanticObjectId) -> datetime | None:
        """Return when this member read the notification, or ``None``."""
        return next((receipt.read_at for receipt in self.read_by if receipt.user_id == user_id), None)

    class Settings:
        name = "notifications"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("organization_id", 1), ("created_at", -1)]),
            IndexModel([("organization_id", 1), ("user_id", 1), ("read_by.user_id", 1)]),
            IndexModel(
                [("organization_id", 1), ("dedupe_key", 1)],
                unique=True,
                partialFilterExpression={"dedupe_key": {"$type": "string"}},
                name="notification_dedupe_unique",
            ),
        ]
