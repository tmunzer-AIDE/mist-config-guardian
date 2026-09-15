"""The janitor closes restores whose worker stopped, and only those.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_executor import (
    RestoreExecutor,
    RestoreOwnershipLostError,
    _RunContext,
)
from mist_config_guardian_backend.services.restore_lease import MemoryRestoreLeaseStore, RestoreLeaseLostError
from mist_config_guardian_backend.services.restore_planner import RestoreOperationState, SafetySnapshotEntry
from mist_config_guardian_backend.services.restore_recovery import INTERRUPTED_REASON, RestoreRecoveryService
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.registry import get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_recovery"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


class _Notifications:
    def __init__(self) -> None:
        self.failed: list[str] = []

    async def notify_restore_failed(self, *, organization_id, restore_id, reason, user_id=None):  # noqa: ARG002
        self.failed.append(reason)


def _settings() -> Settings:
    return Settings(environment="test", credential_encryption_key="test-key")


def _action(order: int, status: RestoreActionStatus) -> RestoreAction:
    return RestoreAction(
        logical_object_id=PydanticObjectId(),
        source_version_id=PydanticObjectId(),
        order=order,
        action=RestoreActionType.UPDATE,
        scope="site",
        object_type="wlans",
        object_name=f"wlan-{order}",
        current_mist_id=f"mist-{order}",
        site_mist_id="site-a",
        protected_configuration={},
        status=status,
    )


async def _running(*, minutes_ago: int, actions: list[RestoreAction]) -> RestoreOperation:
    identifier = PydanticObjectId()
    stamp = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    operation = RestoreOperation(
        id=identifier,
        organization_id=PydanticObjectId(),
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=actions,
        encrypted_delegated_credential=CredentialVault(_settings()).encrypt_for_context(
            "api-token", context=f"restore:{identifier}"
        ),
        delegated_credential_expires_at=stamp + timedelta(minutes=15),
        started_at=stamp,
        created_at=stamp,
        updated_at=stamp,
    )
    await operation.insert()
    return operation


def _service(notifications: _Notifications, leases: MemoryRestoreLeaseStore) -> RestoreRecoveryService:
    settings = _settings()
    return RestoreRecoveryService(settings, CredentialVault(settings), notifications=notifications, leases=leases)


_LEASE_TTL = timedelta(minutes=15)


async def test_a_stale_run_with_a_write_in_flight_becomes_compensable() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(
        minutes_ago=20,
        actions=[
            _action(0, RestoreActionStatus.COMPLETED),
            _action(1, RestoreActionStatus.EXECUTING),
            _action(2, RestoreActionStatus.PENDING),
        ],
    )
    fresh = await _running(minutes_ago=1, actions=[_action(0, RestoreActionStatus.EXECUTING)])
    notifications = _Notifications()
    leases = MemoryRestoreLeaseStore()
    await leases.acquire(stale.organization_id, stale.id, ttl=_LEASE_TTL)
    await leases.acquire(fresh.organization_id, fresh.id, ttl=_LEASE_TTL)

    assert await _service(notifications, leases).recover_interrupted() == 1

    assert await leases.acquire(stale.organization_id, PydanticObjectId(), ttl=_LEASE_TTL) is True
    assert await leases.acquire(fresh.organization_id, PydanticObjectId(), ttl=_LEASE_TTL) is False

    closed = await RestoreOperation.get(stale.id)
    assert closed is not None
    assert closed.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert closed.actions[1].status is RestoreActionStatus.FAILED
    assert closed.actions[1].outcome_unknown is True
    assert closed.failure_action_order == 1
    assert closed.encrypted_delegated_credential is None
    assert closed.delegated_credential_expires_at is None
    assert closed.completed_at is not None
    assert INTERRUPTED_REASON in closed.preflight_errors
    untouched = await RestoreOperation.get(fresh.id)
    assert untouched is not None
    assert untouched.status is RestoreStatus.RUNNING
    assert untouched.encrypted_delegated_credential is not None
    assert notifications.failed == [INTERRUPTED_REASON]


async def test_a_stale_run_that_never_wrote_fails() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(minutes_ago=30, actions=[_action(0, RestoreActionStatus.PENDING)])

    assert await _service(_Notifications(), MemoryRestoreLeaseStore()).recover_interrupted() == 1

    closed = await RestoreOperation.get(stale.id)
    assert closed is not None
    assert closed.status is RestoreStatus.FAILED


async def test_a_run_that_heartbeats_before_the_janitor_writes_is_left_alone() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    stale = await _running(minutes_ago=30, actions=[_action(0, RestoreActionStatus.EXECUTING)])
    observed = await RestoreOperation.get(stale.id)
    assert observed is not None
    await RestoreOperation.get_pymongo_collection().update_one(
        {"_id": stale.id}, {"$set": {"updated_at": datetime.now(UTC)}}
    )
    notifications = _Notifications()

    service = _service(notifications, MemoryRestoreLeaseStore())
    assert await service._interrupt(observed, datetime.now(UTC)) is False  # noqa: SLF001

    alive = await RestoreOperation.get(stale.id)
    assert alive is not None
    assert alive.status is RestoreStatus.RUNNING
    assert notifications.failed == []


# ----------------------------------------------- a worker the janitor overtook


_LIVE = {"name": "wlan-0"}


class _Client:
    """Records Mist writes, optionally letting something happen while one is in flight."""

    def __init__(self, during_write=None) -> None:
        self.writes: list[str] = []
        self.during_write = during_write

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        return dict(_LIVE)

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        self.writes.append(object_id)
        if self.during_write is not None:
            await self.during_write()
        return dict(configuration)


def _context(worker: RestoreOperation) -> _RunContext:
    """A pass whose safety snapshot still matches what the fake client reads."""
    assert worker.id is not None
    definition = get_definition("site", "wlans")
    assert definition is not None
    action = worker.actions[0]
    entry = SafetySnapshotEntry(
        logical_object_id=action.logical_object_id,
        order=action.order,
        action=action.action,
        scope=action.scope,
        object_type=action.object_type,
        object_name=action.object_name,
        mist_object_id=action.current_mist_id,
        site_mist_id=action.site_mist_id,
        existed=True,
        configuration=dict(_LIVE),
        configuration_hash=configuration_hash(_LIVE, ignored_fields=definition.ignored_fields),
    )
    state = RestoreOperationState(
        organization_id=worker.organization_id,
        operation_id=worker.id,
        plan_hash="plan-hash",
        safety_snapshot=[entry],
    )
    return _RunContext(state=state, snapshot={entry.order: entry}, recreated_sites=frozenset(), compensating=False)


def _organization() -> Organization:
    return Organization.model_construct(
        id=PydanticObjectId(),
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
    )


def _executor(leases: MemoryRestoreLeaseStore) -> RestoreExecutor:
    settings = _settings()
    return RestoreExecutor(
        CredentialVault(settings), store=object(), notifications=_Notifications(), verifier=object(), leases=leases
    )


async def _janitor_closes_every_run(leases: MemoryRestoreLeaseStore | None = None) -> None:
    # Far enough ahead that every stored heartbeat is past the timeout.
    await _service(_Notifications(), leases or MemoryRestoreLeaseStore()).recover_interrupted(
        now=datetime.now(UTC) + timedelta(hours=1)
    )


async def _still_closed(operation_id: PydanticObjectId) -> RestoreOperation:
    stored = await RestoreOperation.get(operation_id)
    assert stored is not None
    assert stored.status is not RestoreStatus.RUNNING
    assert INTERRUPTED_REASON in stored.preflight_errors
    assert stored.encrypted_delegated_credential is None
    assert stored.delegated_credential_expires_at is None
    return stored


@pytest.mark.parametrize("janitor_lease", ["released", "kept"])
async def test_a_worker_heartbeat_cannot_reopen_a_run_the_janitor_closed(janitor_lease: str) -> None:
    janitor_released_the_lease = janitor_lease == "released"
    await RestoreOperation.get_pymongo_collection().delete_many({})
    running = await _running(minutes_ago=1, actions=[_action(0, RestoreActionStatus.PENDING)])
    worker = await RestoreOperation.get(running.id)
    assert worker is not None
    leases = MemoryRestoreLeaseStore()
    await leases.acquire(running.organization_id, running.id, ttl=_LEASE_TTL)
    executor = _executor(leases)

    await executor._heartbeat(worker)  # noqa: SLF001
    beating = await RestoreOperation.get(running.id)
    assert beating is not None
    assert beating.updated_at > running.updated_at
    await _janitor_closes_every_run(leases if janitor_released_the_lease else None)

    # Released with the close, the lease is gone; still held, the status guard refuses the beat.
    expected = RestoreLeaseLostError if janitor_released_the_lease else RestoreOwnershipLostError
    with pytest.raises(expected):
        await executor._heartbeat(worker)  # noqa: SLF001

    closed = await _still_closed(running.id)
    assert closed.status is RestoreStatus.FAILED


async def test_a_worker_cannot_start_a_write_on_a_run_the_janitor_closed() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    running = await _running(minutes_ago=1, actions=[_action(0, RestoreActionStatus.PENDING)])
    worker = await RestoreOperation.get(running.id)
    assert worker is not None
    await _janitor_closes_every_run()
    client = _Client()

    with pytest.raises(RestoreOwnershipLostError):
        await _executor(MemoryRestoreLeaseStore())._execute_action(  # noqa: SLF001
            client, _organization(), worker, 0, {}, _context(worker)
        )

    assert client.writes == []
    closed = await _still_closed(running.id)
    assert closed.actions[0].status is RestoreActionStatus.PENDING


async def test_a_write_mist_applied_after_the_janitor_closed_the_run_stays_unconfirmed() -> None:
    await RestoreOperation.get_pymongo_collection().delete_many({})
    running = await _running(minutes_ago=1, actions=[_action(0, RestoreActionStatus.PENDING)])
    worker = await RestoreOperation.get(running.id)
    assert worker is not None
    client = _Client(during_write=_janitor_closes_every_run)

    with pytest.raises(RestoreOwnershipLostError):
        await _executor(MemoryRestoreLeaseStore())._execute_action(  # noqa: SLF001
            client, _organization(), worker, 0, {}, _context(worker)
        )

    assert client.writes == ["mist-0"]
    closed = await _still_closed(running.id)
    assert closed.status is RestoreStatus.COMPENSATION_AVAILABLE
    assert closed.actions[0].status is RestoreActionStatus.FAILED
    assert closed.actions[0].outcome_unknown is True
