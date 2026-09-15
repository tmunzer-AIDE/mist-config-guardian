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
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_recovery import INTERRUPTED_REASON, RestoreRecoveryService

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


def _service(notifications: _Notifications) -> RestoreRecoveryService:
    settings = _settings()
    return RestoreRecoveryService(settings, CredentialVault(settings), notifications=notifications)


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

    assert await _service(notifications).recover_interrupted() == 1

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

    assert await _service(_Notifications()).recover_interrupted() == 1

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

    assert await _service(notifications)._interrupt(observed, datetime.now(UTC)) is False  # noqa: SLF001

    alive = await RestoreOperation.get(stale.id)
    assert alive is not None
    assert alive.status is RestoreStatus.RUNNING
    assert notifications.failed == []
