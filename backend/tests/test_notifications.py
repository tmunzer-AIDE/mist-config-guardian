"""Notification service and API tests."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.api.dependencies import get_current_user, require_organization
from mist_config_guardian_backend.api.routes.notifications import get_notification_service
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.notification import (
    Notification,
    NotificationKind,
    NotificationSeverity,
    NotificationTarget,
)
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.services.notifications import (
    NotificationDraft,
    NotificationService,
    is_mandatory,
    visibility_criteria,
)

ORGANIZATION_ID = PydanticObjectId()
USER_ID = PydanticObjectId()
OTHER_USER_ID = PydanticObjectId()


class _MemoryNotificationStore:
    """In-memory stand-in that honours the criteria documents the service builds."""

    def __init__(self) -> None:
        self.items: list[Notification] = []
        self._dedupe: set[tuple[PydanticObjectId, str]] = set()
        self._clock = datetime(2026, 1, 1, tzinfo=UTC)

    async def insert(self, draft: NotificationDraft) -> Notification:
        if draft.dedupe_key is not None:
            key = (draft.organization_id, draft.dedupe_key)
            if key in self._dedupe:
                msg = "E11000 duplicate key error: notification_dedupe_unique"
                raise DuplicateKeyError(msg)
            self._dedupe.add(key)
        self._clock += timedelta(seconds=1)
        notification = Notification.model_construct(
            id=PydanticObjectId(),
            organization_id=draft.organization_id,
            user_id=draft.user_id,
            kind=draft.kind,
            severity=draft.severity,
            title=draft.title,
            body=draft.body,
            target=draft.target,
            target_params=dict(draft.target_params),
            mandatory=draft.mandatory,
            read_at=None,
            dedupe_key=draft.dedupe_key,
            created_at=self._clock,
            updated_at=self._clock,
        )
        self.items.append(notification)
        return notification

    async def find_one(self, criteria: Mapping[str, object]) -> Notification | None:
        return next((item for item in self._match(criteria)), None)

    async def count(self, criteria: Mapping[str, object]) -> int:
        return len(self._match(criteria))

    async def page(
        self,
        criteria: Mapping[str, object],
        *,
        skip: int,
        limit: int,
    ) -> list[Notification]:
        ordered = sorted(self._match(criteria), key=lambda item: item.created_at, reverse=True)
        return ordered[skip : skip + limit]

    async def mark_read(self, criteria: Mapping[str, object], read_at: datetime) -> int:
        matched = self._match(criteria)
        for item in matched:
            item.read_at = read_at
        return len(matched)

    def _match(self, criteria: Mapping[str, object]) -> list[Notification]:
        return [item for item in self.items if self._matches(item, criteria)]

    @staticmethod
    def _matches(item: Notification, criteria: Mapping[str, object]) -> bool:
        for field, expected in criteria.items():
            actual = item.id if field == "_id" else getattr(item, field)
            if isinstance(expected, dict):
                if "$in" in expected and actual not in expected["$in"]:
                    return False
            elif actual != expected:
                return False
        return True


def _service() -> tuple[NotificationService, _MemoryNotificationStore]:
    store = _MemoryNotificationStore()
    return NotificationService(store), store


def _viewer() -> User:
    return User.model_construct(
        id=USER_ID,
        email="viewer@example.com",
        display_name="Viewer",
        password_hash="unused",
        role=UserRole.VIEWER,
        is_active=True,
    )


def _organization() -> Organization:
    return Organization.model_construct(
        id=ORGANIZATION_ID,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
    )


def _app_with(service: NotificationService) -> object:
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[get_current_user] = _viewer
    app.dependency_overrides[require_organization] = _organization
    app.dependency_overrides[get_notification_service] = lambda: service
    return app


# --------------------------------------------------------------------- rules


def test_mandatory_rules_cover_the_never_suppressible_alerts() -> None:
    assert is_mandatory(NotificationKind.WEBHOOK, NotificationSeverity.WARNING)
    assert is_mandatory(NotificationKind.SNAPSHOT, NotificationSeverity.CRITICAL)
    assert is_mandatory(NotificationKind.RESTORE, NotificationSeverity.CRITICAL)
    assert is_mandatory(NotificationKind.CREDENTIAL, NotificationSeverity.CRITICAL)
    assert not is_mandatory(NotificationKind.SNAPSHOT, NotificationSeverity.OK)
    assert not is_mandatory(NotificationKind.APPROVAL, NotificationSeverity.INFO)


async def test_emit_forces_mandatory_even_when_caller_says_otherwise() -> None:
    service, _ = _service()

    notification = await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.SNAPSHOT,
        severity=NotificationSeverity.CRITICAL,
        title="Snapshot failed",
        mandatory=False,
    )

    assert notification is not None
    assert notification.mandatory is True


async def test_emit_keeps_explicit_mandatory_for_unlisted_pairs() -> None:
    service, _ = _service()

    forced = await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.APPROVAL,
        severity=NotificationSeverity.INFO,
        title="Approval",
        mandatory=True,
    )
    plain = await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.APPROVAL,
        severity=NotificationSeverity.INFO,
        title="Approval",
    )

    assert forced is not None
    assert forced.mandatory is True
    assert plain is not None
    assert plain.mandatory is False


async def test_emit_returns_none_on_dedupe_collision_instead_of_raising() -> None:
    service, store = _service()

    first = await service.notify_snapshot_failed(
        organization_id=ORGANIZATION_ID,
        reason="Mist rejected the request",
        manifest_id="manifest-1",
    )
    second = await service.notify_snapshot_failed(
        organization_id=ORGANIZATION_ID,
        reason="Mist rejected the request",
        manifest_id="manifest-1",
    )

    assert first is not None
    assert second is None
    assert len(store.items) == 1


async def test_emitters_set_deep_link_targets() -> None:
    service, _ = _service()

    impact = await service.notify_impact_detected(
        organization_id=ORGANIZATION_ID,
        change_group_id="group-7",
        summary="Coverage dropped on 3 access points",
    )
    restore = await service.notify_restore_failed(
        organization_id=ORGANIZATION_ID,
        restore_id="restore-2",
        reason="Dependency apply failed",
        user_id=USER_ID,
    )
    gap = await service.notify_webhook_gap(organization_id=ORGANIZATION_ID, gap_minutes=45)
    credential = await service.notify_credential_invalid(
        organization_id=ORGANIZATION_ID,
        reason="Token revoked",
    )

    assert impact is not None
    assert impact.target is NotificationTarget.CHANGES
    assert impact.target_params == {"changeGroupId": "group-7"}
    assert impact.mandatory is True
    assert restore is not None
    assert restore.target is NotificationTarget.RESTORE
    assert restore.target_params == {"restoreId": "restore-2"}
    assert restore.user_id == USER_ID
    assert gap is not None
    assert gap.mandatory is True
    assert credential is not None
    assert credential.mandatory is True


def test_visibility_criteria_includes_organization_wide_notifications() -> None:
    criteria = visibility_criteria(ORGANIZATION_ID, USER_ID, unread_only=True)

    assert criteria == {
        "organization_id": ORGANIZATION_ID,
        "user_id": {"$in": [None, USER_ID]},
        "read_at": None,
    }


# ---------------------------------------------------------------- visibility


async def _seed(service: NotificationService) -> None:
    await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.SNAPSHOT,
        severity=NotificationSeverity.OK,
        title="Organization wide",
    )
    await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.APPROVAL,
        severity=NotificationSeverity.INFO,
        title="Mine",
        user_id=USER_ID,
    )
    await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.APPROVAL,
        severity=NotificationSeverity.INFO,
        title="Someone else",
        user_id=OTHER_USER_ID,
    )
    await service.emit(
        organization_id=PydanticObjectId(),
        kind=NotificationKind.SNAPSHOT,
        severity=NotificationSeverity.OK,
        title="Other organization",
    )


async def test_list_for_hides_other_users_and_other_organizations() -> None:
    service, _ = _service()
    await _seed(service)

    items, total = await service.list_for(ORGANIZATION_ID, USER_ID)

    assert total == 2
    assert [item.title for item in items] == ["Mine", "Organization wide"]


async def test_list_for_paginates_newest_first() -> None:
    service, _ = _service()
    await _seed(service)

    items, total = await service.list_for(ORGANIZATION_ID, USER_ID, skip=1, limit=1)

    assert total == 2
    assert [item.title for item in items] == ["Organization wide"]


async def test_unread_count_and_mark_read_are_scoped_to_the_caller() -> None:
    service, store = _service()
    await _seed(service)

    assert await service.unread_count(ORGANIZATION_ID, USER_ID) == 2

    mine = next(item for item in store.items if item.title == "Mine")
    assert mine.id is not None
    assert await service.mark_read(ORGANIZATION_ID, USER_ID, mine.id) is True
    assert await service.unread_count(ORGANIZATION_ID, USER_ID) == 1

    theirs = next(item for item in store.items if item.title == "Someone else")
    assert theirs.id is not None
    assert await service.mark_read(ORGANIZATION_ID, USER_ID, theirs.id) is False
    assert theirs.read_at is None


async def test_mark_read_is_idempotent_for_an_already_read_notification() -> None:
    service, store = _service()
    await _seed(service)
    mine = next(item for item in store.items if item.title == "Mine")
    assert mine.id is not None

    assert await service.mark_read(ORGANIZATION_ID, USER_ID, mine.id) is True
    assert await service.mark_read(ORGANIZATION_ID, USER_ID, mine.id) is True


async def test_mark_read_reports_missing_notifications() -> None:
    service, _ = _service()

    assert await service.mark_read(ORGANIZATION_ID, USER_ID, PydanticObjectId()) is False


async def test_mark_all_read_only_touches_visible_unread_notifications() -> None:
    service, store = _service()
    await _seed(service)

    updated = await service.mark_all_read(ORGANIZATION_ID, USER_ID)

    assert updated == 2
    assert await service.unread_count(ORGANIZATION_ID, USER_ID) == 0
    theirs = next(item for item in store.items if item.title == "Someone else")
    assert theirs.read_at is None
    assert await service.mark_all_read(ORGANIZATION_ID, USER_ID) == 0


# ----------------------------------------------------------------------- api


async def test_viewer_can_list_notifications() -> None:
    service, _ = _service()
    await _seed(service)
    app = _app_with(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/notifications")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["unread"] == 2
    assert [item["title"] for item in payload["items"]] == ["Mine", "Organization wide"]
    assert payload["items"][0]["read"] is False


async def test_unread_only_filter_is_applied() -> None:
    service, store = _service()
    await _seed(service)
    await service.mark_all_read(ORGANIZATION_ID, USER_ID)
    await service.emit(
        organization_id=ORGANIZATION_ID,
        kind=NotificationKind.WEBHOOK,
        severity=NotificationSeverity.WARNING,
        title="Fresh",
    )
    app = _app_with(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(
            f"/api/v1/organizations/{ORGANIZATION_ID}/notifications",
            params={"unread_only": "true"},
        )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == ["Fresh"]
    assert len(store.items) == 5


async def test_unread_count_endpoint() -> None:
    service, _ = _service()
    await _seed(service)
    app = _app_with(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/notifications/unread-count")

    assert response.status_code == 200
    assert response.json() == {"unread": 2}


async def test_mark_read_endpoint_returns_404_for_another_users_notification() -> None:
    service, store = _service()
    await _seed(service)
    theirs = next(item for item in store.items if item.title == "Someone else")
    app = _app_with(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        allowed = await client.post(
            f"/api/v1/organizations/{ORGANIZATION_ID}/notifications/"
            f"{next(item.id for item in store.items if item.title == 'Mine')}/read"
        )
        denied = await client.post(f"/api/v1/organizations/{ORGANIZATION_ID}/notifications/{theirs.id}/read")

    assert allowed.status_code == 204
    assert denied.status_code == 404


async def test_read_all_endpoint_reports_the_updated_count() -> None:
    service, _ = _service()
    await _seed(service)
    app = _app_with(service)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(f"/api/v1/organizations/{ORGANIZATION_ID}/notifications/read-all")

    assert response.status_code == 200
    assert response.json() == {"updated": 2}


@pytest.mark.parametrize(
    "path",
    ["", "/unread-count"],
)
async def test_notification_endpoints_require_authentication(path: str) -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/organizations/{ORGANIZATION_ID}/notifications{path}")

    assert response.status_code == 401


async def test_success_emitters_are_informational_and_deduplicated() -> None:
    service, _ = _service()

    snapshot = await service.notify_snapshot_completed(
        organization_id=ORGANIZATION_ID,
        manifest_id="manifest-9",
        object_count=1284,
    )
    restore = await service.notify_restore_completed(
        organization_id=ORGANIZATION_ID,
        restore_id="restore-9",
        applied_count=12,
        user_id=USER_ID,
    )
    approval = await service.notify_approval_requested(
        organization_id=ORGANIZATION_ID,
        restore_id="restore-9",
        approval_id="approval-3",
        requested_by="operator@example.com",
    )

    assert snapshot is not None
    assert snapshot.mandatory is False
    assert snapshot.severity is NotificationSeverity.OK
    assert snapshot.target is NotificationTarget.HISTORY
    assert snapshot.target_params == {"manifestId": "manifest-9"}
    assert restore is not None
    assert restore.mandatory is False
    assert restore.target_params == {"restoreId": "restore-9"}
    assert approval is not None
    assert approval.target_params == {"restoreId": "restore-9", "approvalId": "approval-3"}
    assert (
        await service.notify_snapshot_completed(
            organization_id=ORGANIZATION_ID,
            manifest_id="manifest-9",
            object_count=1284,
        )
        is None
    )


async def test_webhook_gap_dedupes_per_gap_window() -> None:
    service, store = _service()
    first_seen = datetime(2026, 3, 1, 12, tzinfo=UTC)

    first = await service.notify_webhook_gap(
        organization_id=ORGANIZATION_ID,
        gap_minutes=45,
        last_received_at=first_seen,
    )
    repeat = await service.notify_webhook_gap(
        organization_id=ORGANIZATION_ID,
        gap_minutes=90,
        last_received_at=first_seen,
    )
    later = await service.notify_webhook_gap(
        organization_id=ORGANIZATION_ID,
        gap_minutes=45,
        last_received_at=datetime(2026, 3, 2, 12, tzinfo=UTC),
    )

    assert first is not None
    assert "45 minutes" in first.body
    assert repeat is None
    assert later is not None
    assert len(store.items) == 2


async def test_snapshot_failure_without_a_manifest_is_never_deduplicated() -> None:
    service, store = _service()

    for _ in range(2):
        failure = await service.notify_snapshot_failed(
            organization_id=ORGANIZATION_ID,
            reason="Mist API unreachable",
        )
        assert failure is not None
        assert failure.mandatory is True
        assert failure.target_params == {}

    assert len(store.items) == 2


async def test_dedupe_keys_are_truncated_to_stay_indexable() -> None:
    service, store = _service()

    first = await service.notify_credential_invalid(
        organization_id=ORGANIZATION_ID,
        reason="x" * 4000,
    )
    second = await service.notify_credential_invalid(
        organization_id=ORGANIZATION_ID,
        reason="x" * 4000,
    )

    assert first is not None
    assert first.dedupe_key is not None
    assert len(first.dedupe_key) <= 200
    assert second is None
    assert len(store.items) == 1
