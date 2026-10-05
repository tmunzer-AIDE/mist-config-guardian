"""Database-backed checks of the reconciling snapshot a verified restore queues.

The organization has one active snapshot manifest at a time, so the manifest
must exist before the task does: a redelivered task then resumes it instead of
opening a second one and finding the first in its way.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from celery.exceptions import CeleryError
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreMode, RestoreOperation, RestoreStatus
from mist_config_guardian_backend.models.snapshot import SnapshotKind, SnapshotManifest, SnapshotStatus
from mist_config_guardian_backend.services import restore_verification
from mist_config_guardian_backend.services.restore_verification import (
    RestoreVerificationService,
    queue_post_restore_snapshot,
)
from mist_config_guardian_backend.services.snapshots import SnapshotInProgressError

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_post_snapshot"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[SnapshotManifest])
    yield
    await client.drop_database(DATABASE)
    await client.close()


class _Queue:
    """Celery's ``send_task``, recording what was sent or refusing like an unreachable broker."""

    def __init__(self, *, available: bool = True) -> None:
        self.available = available
        self.sent: list[tuple[str, list[str], str | None]] = []

    def send_task(self, name: str, *, args: list[str], task_id: str | None = None) -> None:
        if not self.available:
            msg = "broker unreachable"
            raise CeleryError(msg)
        self.sent.append((name, args, task_id))


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> _Queue:
    fake = _Queue()
    monkeypatch.setattr(restore_verification, "celery_app", fake)
    return fake


async def _active(organization_id: PydanticObjectId) -> list[SnapshotManifest]:
    return await SnapshotManifest.find(
        SnapshotManifest.organization_id == organization_id,
        SnapshotManifest.active == True,  # noqa: E712 - a MongoDB filter, not a truth test
    ).to_list()


async def test_the_reconciling_snapshot_is_queued_with_the_manifest_it_resumes(queue: _Queue) -> None:
    organization_id = PydanticObjectId()

    task_id = await queue_post_restore_snapshot(organization_id)

    [manifest] = await _active(organization_id)
    assert manifest.kind is SnapshotKind.RECONCILIATION
    assert manifest.status is SnapshotStatus.PENDING
    assert queue.sent == [
        ("snapshots.collect", [str(organization_id), SnapshotKind.RECONCILIATION.value, str(manifest.id)], task_id)
    ]


async def test_no_reconciling_snapshot_is_queued_while_another_snapshot_runs(queue: _Queue) -> None:
    organization_id = PydanticObjectId()
    running = SnapshotManifest(organization_id=organization_id, kind=SnapshotKind.MANUAL, status=SnapshotStatus.RUNNING)
    await running.insert()

    with pytest.raises(SnapshotInProgressError):
        await queue_post_restore_snapshot(organization_id)

    assert queue.sent == []
    assert [manifest.id for manifest in await _active(organization_id)] == [running.id]


async def test_a_manifest_whose_task_could_not_be_queued_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(restore_verification, "celery_app", _Queue(available=False))
    organization_id = PydanticObjectId()

    assert await queue_post_restore_snapshot(organization_id) is None

    # Left active, it would refuse every snapshot of the organization until released as stale.
    assert await _active(organization_id) == []
    [manifest] = await SnapshotManifest.find(SnapshotManifest.organization_id == organization_id).to_list()
    assert manifest.status is SnapshotStatus.FAILED


class _NoState:
    async def load(self, _organization_id, _operation_id):
        return None

    async def save(self, _state):
        return None


async def test_a_restore_verified_while_another_snapshot_runs_is_not_failed_by_it(queue: _Queue) -> None:
    organization_id = PydanticObjectId()
    await SnapshotManifest(organization_id=organization_id, kind=SnapshotKind.MANUAL).insert()
    operation = RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=[],
    )

    async def _reopen(_organization_id, _site_ids):
        return []

    result = await RestoreVerificationService(_NoState(), reopen_monitoring=_reopen).verify(
        None, None, operation, id_map={}, applied={}
    )

    assert result.verified is True
    assert result.post_snapshot_id is None
    [check] = [check for check in result.checks if check.label == "Post-restore snapshot"]
    assert check.status == "skipped"
    assert check.detail == "Another snapshot of the organization is already in progress"
    assert queue.sent == []
