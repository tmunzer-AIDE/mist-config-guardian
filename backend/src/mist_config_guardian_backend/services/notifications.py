"""In-application notification emission and inbox queries.

Other workstreams should never insert :class:`Notification` documents directly.
They call :class:`NotificationService`, which owns the mandatory-alert rules and
the deduplication contract so a critical alert can never be created in a
suppressible form.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Protocol

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.notification import (
    Notification,
    NotificationKind,
    NotificationSeverity,
    NotificationTarget,
)

_DEFAULT_PAGE_SIZE = 50
# Dedupe keys are indexed, so an emitter that folds a long failure reason into
# its key must not be able to overflow the MongoDB index key limit.
_MAX_DEDUPE_KEY_LENGTH = 200

# Delivery gaps, snapshot failures, restore failures, and credential
# verification failures must always reach the operator, even once per-user or
# per-organization muting exists. The table is the single source of truth.
_MANDATORY_RULES: Mapping[tuple[NotificationKind, NotificationSeverity], bool] = MappingProxyType(
    {
        (NotificationKind.WEBHOOK, NotificationSeverity.WARNING): True,
        (NotificationKind.WEBHOOK, NotificationSeverity.CRITICAL): True,
        (NotificationKind.SNAPSHOT, NotificationSeverity.CRITICAL): True,
        (NotificationKind.RESTORE, NotificationSeverity.CRITICAL): True,
        (NotificationKind.CREDENTIAL, NotificationSeverity.WARNING): True,
        (NotificationKind.CREDENTIAL, NotificationSeverity.CRITICAL): True,
        (NotificationKind.RECONCILIATION, NotificationSeverity.CRITICAL): True,
        (NotificationKind.CRITICAL, NotificationSeverity.CRITICAL): True,
    }
)


def is_mandatory(kind: NotificationKind, severity: NotificationSeverity) -> bool:
    """Report whether this notification class may never be suppressed."""
    return _MANDATORY_RULES.get((kind, severity), False)


def visibility_criteria(
    organization_id: PydanticObjectId,
    user_id: PydanticObjectId | None,
    *,
    unread_only: bool = False,
) -> dict[str, object]:
    """Build the filter selecting notifications one user may read.

    A notification without a ``user_id`` is organization-wide and visible to
    every member; a notification carrying one is private to that member.
    """
    criteria: dict[str, object] = {
        "organization_id": organization_id,
        "user_id": {"$in": [None, user_id]},
    }
    if unread_only:
        criteria["read_at"] = None
    return criteria


@dataclass(frozen=True, slots=True)
class NotificationDraft:
    """A notification the service has fully resolved but not yet persisted."""

    organization_id: PydanticObjectId
    kind: NotificationKind
    severity: NotificationSeverity
    title: str
    body: str
    target: NotificationTarget
    target_params: dict[str, str]
    user_id: PydanticObjectId | None
    mandatory: bool
    dedupe_key: str | None


class NotificationStore(Protocol):
    """Persistence operations the notification service depends on."""

    async def insert(self, draft: NotificationDraft) -> Notification:
        """Persist a new notification, raising ``DuplicateKeyError`` on dedupe collision."""

    async def find_one(self, criteria: Mapping[str, object]) -> Notification | None:
        """Return the first notification matching the criteria."""

    async def count(self, criteria: Mapping[str, object]) -> int:
        """Count notifications matching the criteria."""

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[Notification]:
        """Return one newest-first page of notifications matching the criteria."""

    async def mark_read(self, criteria: Mapping[str, object], read_at: datetime) -> int:
        """Stamp matching notifications as read and return the modified count."""


class BeanieNotificationStore:
    """MongoDB-backed notification storage."""

    async def insert(self, draft: NotificationDraft) -> Notification:
        """Persist a new notification."""
        notification = Notification(
            organization_id=draft.organization_id,
            user_id=draft.user_id,
            kind=draft.kind,
            severity=draft.severity,
            title=draft.title,
            body=draft.body,
            target=draft.target,
            target_params=dict(draft.target_params),
            mandatory=draft.mandatory,
            dedupe_key=draft.dedupe_key,
        )
        return await notification.insert()

    async def find_one(self, criteria: Mapping[str, object]) -> Notification | None:
        """Return the first notification matching the criteria."""
        return await Notification.find_one(dict(criteria))

    async def count(self, criteria: Mapping[str, object]) -> int:
        """Count notifications matching the criteria."""
        return await Notification.find(dict(criteria)).count()

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[Notification]:
        """Return one newest-first page of notifications matching the criteria."""
        return await Notification.find(dict(criteria)).sort("-created_at").skip(skip).limit(limit).to_list()

    async def mark_read(self, criteria: Mapping[str, object], read_at: datetime) -> int:
        """Stamp matching notifications as read and return the modified count."""
        result = await Notification.get_pymongo_collection().update_many(
            dict(criteria),
            {"$set": {"read_at": read_at, "updated_at": utc_now()}},
        )
        return int(result.modified_count)


class NotificationService:
    """Create and read organization-scoped in-application notifications."""

    def __init__(self, store: NotificationStore | None = None) -> None:
        self._store: NotificationStore = store or BeanieNotificationStore()

    # ------------------------------------------------------------------ write
    async def emit(  # noqa: PLR0913 - one keyword per persisted notification field
        self,
        *,
        organization_id: PydanticObjectId,
        kind: NotificationKind,
        severity: NotificationSeverity,
        title: str,
        body: str = "",
        target: NotificationTarget = NotificationTarget.OVERVIEW,
        target_params: Mapping[str, str] | None = None,
        user_id: PydanticObjectId | None = None,
        mandatory: bool = False,
        dedupe_key: str | None = None,
    ) -> Notification | None:
        """Persist one notification, or return ``None`` when it already exists.

        ``dedupe_key`` is unique per organization. A collision means an
        equivalent notification is already in the feed, which is a normal
        outcome for repeated detections rather than an error.
        """
        draft = NotificationDraft(
            organization_id=organization_id,
            user_id=user_id,
            kind=kind,
            severity=severity,
            title=title,
            body=body,
            target=target,
            target_params=dict(target_params or {}),
            mandatory=mandatory or is_mandatory(kind, severity),
            dedupe_key=dedupe_key[:_MAX_DEDUPE_KEY_LENGTH] if dedupe_key is not None else None,
        )
        try:
            return await self._store.insert(draft)
        except DuplicateKeyError:
            return None

    # ------------------------------------------------------------------- read
    async def list_for(
        self,
        organization_id: PydanticObjectId,
        user_id: PydanticObjectId | None,
        *,
        unread_only: bool = False,
        skip: int = 0,
        limit: int = _DEFAULT_PAGE_SIZE,
    ) -> tuple[list[Notification], int]:
        """Return one newest-first page visible to the user, and its total."""
        criteria = visibility_criteria(organization_id, user_id, unread_only=unread_only)
        total = await self._store.count(criteria)
        items = await self._store.page(criteria, skip=skip, limit=limit)
        return items, total

    async def unread_count(
        self,
        organization_id: PydanticObjectId,
        user_id: PydanticObjectId | None,
    ) -> int:
        """Count unread notifications visible to the user."""
        return await self._store.count(visibility_criteria(organization_id, user_id, unread_only=True))

    async def mark_read(
        self,
        organization_id: PydanticObjectId,
        user_id: PydanticObjectId | None,
        notification_id: PydanticObjectId,
    ) -> bool:
        """Mark one visible notification read, reporting whether it exists."""
        criteria = visibility_criteria(organization_id, user_id)
        criteria["_id"] = notification_id
        updated = await self._store.mark_read({**criteria, "read_at": None}, utc_now())
        if updated:
            return True
        return await self._store.find_one(criteria) is not None

    async def mark_all_read(
        self,
        organization_id: PydanticObjectId,
        user_id: PydanticObjectId | None,
    ) -> int:
        """Mark every unread visible notification read and return the count."""
        criteria = visibility_criteria(organization_id, user_id, unread_only=True)
        return await self._store.mark_read(criteria, utc_now())

    # -------------------------------------------------------------- emitters
    async def notify_snapshot_completed(
        self,
        *,
        organization_id: PydanticObjectId,
        manifest_id: str,
        object_count: int,
    ) -> Notification | None:
        """Announce a completed snapshot or reconciliation pass."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.SNAPSHOT,
            severity=NotificationSeverity.OK,
            title="Snapshot completed",
            body=f"Captured {object_count} configuration objects.",
            target=NotificationTarget.HISTORY,
            target_params={"manifestId": manifest_id},
            dedupe_key=f"snapshot-completed:{manifest_id}",
        )

    async def notify_snapshot_failed(
        self,
        *,
        organization_id: PydanticObjectId,
        reason: str,
        manifest_id: str | None = None,
    ) -> Notification | None:
        """Raise the mandatory alert for a failed snapshot or reconciliation."""
        target_params = {"manifestId": manifest_id} if manifest_id else {}
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.SNAPSHOT,
            severity=NotificationSeverity.CRITICAL,
            title="Snapshot failed",
            body=reason,
            target=NotificationTarget.HISTORY,
            target_params=target_params,
            dedupe_key=f"snapshot-failed:{manifest_id}" if manifest_id else None,
        )

    async def notify_webhook_gap(
        self,
        *,
        organization_id: PydanticObjectId,
        gap_minutes: int,
        last_received_at: datetime | None = None,
    ) -> Notification | None:
        """Raise the mandatory alert for a Mist webhook delivery gap."""
        marker = last_received_at.isoformat() if last_received_at is not None else "never"
        body = (
            f"No Mist webhook has been accepted for {gap_minutes} minutes. "
            "Configuration changes made in this window may be missing until the next reconciliation."
            if last_received_at is not None
            else "No Mist webhook has ever been accepted for this organization."
        )
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.WEBHOOK,
            severity=NotificationSeverity.WARNING,
            title="Webhook delivery gap detected",
            body=body,
            target=NotificationTarget.SETTINGS,
            target_params={"tab": "webhooks"},
            dedupe_key=f"webhook-gap:{marker}",
        )

    async def notify_credential_invalid(
        self,
        *,
        organization_id: PydanticObjectId,
        reason: str,
    ) -> Notification | None:
        """Raise the mandatory alert for a failed Mist credential verification."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.CREDENTIAL,
            severity=NotificationSeverity.CRITICAL,
            title="Mist credential verification failed",
            body=reason,
            target=NotificationTarget.SETTINGS,
            target_params={"tab": "credentials"},
            dedupe_key=f"credential-invalid:{reason}",
        )

    async def notify_restore_failed(
        self,
        *,
        organization_id: PydanticObjectId,
        restore_id: str,
        reason: str,
        user_id: PydanticObjectId | None = None,
    ) -> Notification | None:
        """Raise the mandatory alert for a failed restore execution."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.RESTORE,
            severity=NotificationSeverity.CRITICAL,
            title="Restore failed",
            body=reason,
            target=NotificationTarget.RESTORE,
            target_params={"restoreId": restore_id},
            user_id=user_id,
            dedupe_key=f"restore-failed:{restore_id}",
        )

    async def notify_restore_completed(
        self,
        *,
        organization_id: PydanticObjectId,
        restore_id: str,
        applied_count: int,
        user_id: PydanticObjectId | None = None,
    ) -> Notification | None:
        """Announce a restore that finished without failures."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.RESTORE,
            severity=NotificationSeverity.OK,
            title="Restore completed",
            body=f"Applied {applied_count} configuration objects.",
            target=NotificationTarget.RESTORE,
            target_params={"restoreId": restore_id},
            user_id=user_id,
            dedupe_key=f"restore-completed:{restore_id}",
        )

    async def notify_approval_requested(
        self,
        *,
        organization_id: PydanticObjectId,
        restore_id: str,
        approval_id: str,
        requested_by: str,
        user_id: PydanticObjectId | None = None,
    ) -> Notification | None:
        """Ask an approver to review a pending restore."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.APPROVAL,
            severity=NotificationSeverity.WARNING,
            title="Restore approval requested",
            body=f"{requested_by} requested approval for a restore.",
            target=NotificationTarget.RESTORE,
            target_params={"restoreId": restore_id, "approvalId": approval_id},
            user_id=user_id,
            dedupe_key=f"approval-requested:{approval_id}" if user_id is None else None,
        )

    async def notify_impact_detected(
        self,
        *,
        organization_id: PydanticObjectId,
        change_group_id: str,
        summary: str,
        severity: NotificationSeverity = NotificationSeverity.CRITICAL,
    ) -> Notification | None:
        """Report a configuration change that degraded the network."""
        return await self.emit(
            organization_id=organization_id,
            kind=NotificationKind.CRITICAL,
            severity=severity,
            title="Harmful change detected",
            body=summary,
            target=NotificationTarget.CHANGES,
            target_params={"changeGroupId": change_group_id},
            dedupe_key=f"impact-detected:{change_group_id}",
        )
