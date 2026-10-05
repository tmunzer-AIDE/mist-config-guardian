"""Database-backed checks of snapshot runs and the captures they record.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import asyncio
import os
from datetime import timedelta
from typing import Self

import httpx
import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.api.dependencies import get_organization_service, require_operator
from mist_config_guardian_backend.api.routes import snapshots as snapshot_routes
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
    VersionEvent,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import snapshots as snapshot_service
from mist_config_guardian_backend.services.snapshots import (
    STALE_MANIFEST_AFTER,
    CaptureContext,
    SnapshotInProgressError,
    SnapshotService,
)
from mist_config_guardian_backend.snapshots.fingerprint import fingerprint
from mist_config_guardian_backend.snapshots.registry import get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "snapshot_capture_records"
NETWORKS = get_definition("org", "networks")

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(
        database=client[DATABASE],
        document_models=[LogicalObject, ObjectIncarnation, ObjectVersion, Organization, SnapshotManifest],
    )
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


def _capture() -> CaptureContext:
    return CaptureContext(snapshot_id=None, site_id=None)


async def _organization(*, encrypted_service_token: str | None = None) -> Organization:
    organization = Organization(
        mist_org_id=str(PydanticObjectId()),
        name="Northwind Retail",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token=encrypted_service_token or "v1:unused",
        service_token_last_four="4f21",
    )
    await organization.insert()
    return organization


async def _versions(logical_id: PydanticObjectId) -> list[ObjectVersion]:
    return await ObjectVersion.find(ObjectVersion.logical_object_id == logical_id).sort("version").to_list()


async def _tombstone(logical: LogicalObject, *, configuration_hash: str | None = None) -> None:
    """Record a deletion the way the audit path does: the last configuration, marked deleted."""
    assert logical.id is not None
    latest = (await _versions(logical.id))[-1]
    await ObjectVersion(
        organization_id=logical.organization_id,
        logical_object_id=logical.id,
        incarnation_id=latest.incarnation_id,
        version=latest.version + 1,
        event=VersionEvent.DELETED,
        configuration=latest.configuration,
        configuration_hash=configuration_hash or latest.configuration_hash,
        is_deleted=True,
    ).insert()
    logical.current_version = latest.version + 1
    logical.is_deleted = True
    await logical.save()


class _Mist:
    """A Mist organization with nothing configured; ``on_fetch`` runs before every read."""

    on_fetch = None

    def __init__(self, *, token: str, region: MistCloudRegion) -> None:
        del token, region

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def fetch(self, definition: object, *, org_id: str, site_id: str | None = None) -> list[dict[str, object]]:
        del definition, org_id, site_id
        if _Mist.on_fetch is not None:
            await _Mist.on_fetch()
        return []


@pytest.fixture
def mist(monkeypatch: pytest.MonkeyPatch) -> type[_Mist]:
    async def _token(*_args: object) -> str:
        return "token"

    _Mist.on_fetch = None
    monkeypatch.setattr(snapshot_service, "MistConfigurationClient", _Mist)
    monkeypatch.setattr(snapshot_service, "service_token", _token)
    return _Mist


# ------------------------------------------------------------- tombstones


async def test_an_object_seen_again_unchanged_after_a_tombstone_is_live_again() -> None:
    organization_id = PydanticObjectId()
    service = SnapshotService(_vault())
    configuration = {"id": "net-back", "name": "Corp", "vlan_id": 10}
    await service.capture_configuration(organization_id, NETWORKS, configuration, _capture())
    logical = await LogicalObject.find_one(LogicalObject.organization_id == organization_id)
    assert logical is not None
    await _tombstone(logical)

    created = await service.capture_configuration(organization_id, NETWORKS, configuration, _capture())

    assert created
    logical = await LogicalObject.get(logical.id)
    assert logical is not None
    assert not logical.is_deleted
    assert logical.current_version == 3
    versions = await _versions(logical.id)
    assert [(item.version, item.event, item.is_deleted) for item in versions] == [
        (1, VersionEvent.INITIAL, False),
        (2, VersionEvent.DELETED, True),
        (3, VersionEvent.CREATED, False),
    ]
    assert versions[-1].configuration_hash == fingerprint(NETWORKS, configuration)
    # Once live again, the next unchanged capture is unchanged.
    assert not await service.capture_configuration(organization_id, NETWORKS, configuration, _capture())


async def test_a_tombstone_with_an_older_digest_does_not_hide_the_object_coming_back() -> None:
    """The structural comparison is a second "unchanged" shortcut; a tombstone must skip it too."""
    organization_id = PydanticObjectId()
    service = SnapshotService(_vault())
    configuration = {"id": "net-legacy", "name": "Legacy", "vlan_id": 20}
    await service.capture_configuration(organization_id, NETWORKS, configuration, _capture())
    logical = await LogicalObject.find_one(LogicalObject.organization_id == organization_id)
    assert logical is not None
    await _tombstone(logical, configuration_hash="digest-under-an-older-policy")

    created = await service.capture_configuration(organization_id, NETWORKS, configuration, _capture())

    assert created
    logical = await LogicalObject.get(logical.id)
    assert logical is not None
    assert not logical.is_deleted
    assert [item.is_deleted for item in await _versions(logical.id)] == [False, True, False]


# ------------------------------------------------------------- concurrency


async def test_two_concurrent_captures_of_a_new_object_record_it_once() -> None:
    organization_id = PydanticObjectId()
    service = SnapshotService(_vault())
    configuration = {"id": "net-race", "name": "Race", "vlan_id": 30}

    results = await asyncio.gather(
        service.capture_configuration(organization_id, NETWORKS, configuration, _capture()),
        service.capture_configuration(organization_id, NETWORKS, configuration, _capture()),
    )

    assert sorted(results) == [False, True]
    logicals = await LogicalObject.find(LogicalObject.organization_id == organization_id).to_list()
    assert len(logicals) == 1
    assert logicals[0].id is not None
    assert await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logicals[0].id).count() == 1
    assert [item.version for item in await _versions(logicals[0].id)] == [1]


async def test_two_concurrent_captures_of_a_changed_object_record_one_version() -> None:
    """A webhook capture and a snapshot read the same change at once."""
    organization_id = PydanticObjectId()
    service = SnapshotService(_vault())
    await service.capture_configuration(
        organization_id, NETWORKS, {"id": "net-r2", "name": "R2", "vlan_id": 1}, _capture()
    )
    changed = {"id": "net-r2", "name": "R2", "vlan_id": 2}

    results = await asyncio.gather(
        service.capture_configuration(organization_id, NETWORKS, changed, _capture()),
        service.capture_configuration(organization_id, NETWORKS, changed, _capture()),
    )

    assert sorted(results) == [False, True]
    logical = await LogicalObject.find_one(LogicalObject.organization_id == organization_id)
    assert logical is not None
    assert logical.id is not None
    assert [item.version for item in await _versions(logical.id)] == [1, 2]
    assert logical.current_version == 2


async def test_two_concurrent_captures_of_different_changes_keep_both() -> None:
    organization_id = PydanticObjectId()
    service = SnapshotService(_vault())
    await service.capture_configuration(
        organization_id, NETWORKS, {"id": "net-r3", "name": "R3", "vlan_id": 1}, _capture()
    )

    first = {"id": "net-r3", "name": "R3", "vlan_id": 2}
    second = {"id": "net-r3", "name": "R3", "vlan_id": 3}

    results = await asyncio.gather(
        service.capture_configuration(organization_id, NETWORKS, first, _capture()),
        service.capture_configuration(organization_id, NETWORKS, second, _capture()),
    )

    assert results == [True, True]
    logical = await LogicalObject.find_one(LogicalObject.organization_id == organization_id)
    assert logical is not None
    assert logical.id is not None
    assert [item.version for item in await _versions(logical.id)] == [1, 2, 3]


# ------------------------------------------------------------ manifests


async def test_a_snapshot_whose_token_cannot_be_read_releases_the_active_slot() -> None:
    organization = await _organization(encrypted_service_token="v1:not-decryptable")
    assert organization.id is not None

    with pytest.raises(Exception):  # noqa: B017, PT011 - whichever decryption error the vault raises
        await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.MANUAL)

    manifest = await SnapshotManifest.find_one(SnapshotManifest.organization_id == organization.id)
    assert manifest is not None
    assert (manifest.status, manifest.active) == (SnapshotStatus.FAILED, False)
    # The next request is not refused as "already in progress".
    await SnapshotManifest(organization_id=organization.id, kind=SnapshotKind.MANUAL).insert()


async def test_a_queued_snapshot_whose_token_cannot_be_read_releases_the_active_slot() -> None:
    organization = await _organization(encrypted_service_token="v1:not-decryptable")
    assert organization.id is not None
    queued = SnapshotManifest(organization_id=organization.id, kind=SnapshotKind.MANUAL)
    await queued.insert()

    with pytest.raises(Exception):  # noqa: B017, PT011 - whichever decryption error the vault raises
        await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.MANUAL, manifest_id=queued.id)

    manifest = await SnapshotManifest.get(queued.id)
    assert manifest is not None
    assert (manifest.status, manifest.active) == (SnapshotStatus.FAILED, False)


@pytest.mark.usefixtures("mist")
async def test_a_redelivered_snapshot_replaces_a_manifest_that_stopped_long_ago() -> None:
    """A worker lost mid-run leaves its manifest active; the next run must not be refused forever."""
    organization = await _organization()
    assert organization.id is not None
    abandoned = SnapshotManifest(
        organization_id=organization.id,
        kind=SnapshotKind.RECONCILIATION,
        status=SnapshotStatus.RUNNING,
        started_at=utc_now() - STALE_MANIFEST_AFTER - timedelta(minutes=1),
    )
    await abandoned.insert()

    manifest = await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.RECONCILIATION)

    assert manifest.status is SnapshotStatus.COMPLETED
    stale = await SnapshotManifest.get(abandoned.id)
    assert stale is not None
    assert (stale.status, stale.active) == (SnapshotStatus.FAILED, False)
    assert stale.errors


@pytest.mark.usefixtures("mist")
async def test_a_snapshot_in_progress_is_left_alone() -> None:
    organization = await _organization()
    assert organization.id is not None
    running = SnapshotManifest(
        organization_id=organization.id,
        kind=SnapshotKind.MANUAL,
        status=SnapshotStatus.RUNNING,
        started_at=utc_now(),
    )
    await running.insert()

    with pytest.raises(SnapshotInProgressError):
        await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.RECONCILIATION)

    current = await SnapshotManifest.get(running.id)
    assert current is not None
    assert (current.status, current.active) == (SnapshotStatus.RUNNING, True)


def _operator() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="operator@example.com",
        display_name="Operator",
        password_hash="unused",
        role=UserRole.OPERATOR,
        is_active=True,
    )


class _Organizations:
    async def get(self, organization_id: PydanticObjectId) -> Organization | None:
        return await Organization.get(organization_id)


async def test_triggering_a_snapshot_replaces_a_manifest_that_stopped_long_ago(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization = await _organization()
    assert organization.id is not None
    abandoned = SnapshotManifest(
        organization_id=organization.id,
        kind=SnapshotKind.MANUAL,
        created_at=utc_now() - STALE_MANIFEST_AFTER - timedelta(minutes=1),
    )
    await abandoned.insert()
    sent: list[list[str]] = []

    def _send_task(_name: str, *, args: list[str]) -> object:
        sent.append(args)
        return type("Task", (), {"id": "task-1"})()

    monkeypatch.setattr(snapshot_routes.celery_app, "send_task", _send_task)
    app = create_app(Settings(environment="test", database_enabled=False))
    app.dependency_overrides[require_operator] = _operator
    app.dependency_overrides[get_organization_service] = _Organizations

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        refused = await client.post(f"/api/v1/organizations/{organization.id}/snapshots", json={"kind": "manual"})
        stale = await SnapshotManifest.get(abandoned.id)
        assert stale is not None
        assert (stale.status, stale.active) == (SnapshotStatus.FAILED, False)
        again = await client.post(f"/api/v1/organizations/{organization.id}/snapshots", json={"kind": "manual"})

    assert refused.status_code == 202
    # Only the abandoned one is released: a fresh request still waits its turn.
    assert again.status_code == 409
    assert len(sent) == 1


# ------------------------------------------------------- initial snapshot


@pytest.mark.usefixtures("mist")
async def test_the_first_completed_snapshot_of_any_kind_marks_the_initial_snapshot() -> None:
    organization = await _organization()
    assert organization.id is not None

    manifest = await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.MANUAL)

    stored = await Organization.get(organization.id)
    assert stored is not None
    assert manifest.completed_at is not None
    assert stored.initial_snapshot_completed_at is not None
    assert abs(stored.initial_snapshot_completed_at - manifest.completed_at) < timedelta(seconds=1)


@pytest.mark.usefixtures("mist")
async def test_a_later_snapshot_keeps_the_first_completion_time() -> None:
    organization = await _organization()
    assert organization.id is not None
    first = (utc_now() - timedelta(days=3)).replace(microsecond=0)
    await Organization.find_one(Organization.id == organization.id).update(
        {"$set": {"initial_snapshot_completed_at": first}}
    )

    await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.INITIAL)

    stored = await Organization.get(organization.id)
    assert stored is not None
    assert stored.initial_snapshot_completed_at == first


async def test_completing_a_snapshot_keeps_credential_changes_made_during_the_crawl(mist: type[_Mist]) -> None:
    """A crawl is long; the organization it read at the start is stale by the time it ends."""
    organization = await _organization()
    assert organization.id is not None

    async def _rotate() -> None:
        await Organization.find_one(Organization.id == organization.id).update(
            {"$set": {"encrypted_webhook_secret": "v1:rotated", "encrypted_service_token": "v1:replaced"}}
        )

    mist.on_fetch = _rotate

    await SnapshotService(_vault()).run(organization.id, kind=SnapshotKind.INITIAL)

    stored = await Organization.get(organization.id)
    assert stored is not None
    assert stored.initial_snapshot_completed_at is not None
    assert (stored.encrypted_webhook_secret, stored.encrypted_service_token) == ("v1:rotated", "v1:replaced")
