"""The MongoDB lease admits one restore per organization.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreLease, RestoreMode, RestoreOperation, RestoreStatus
from mist_config_guardian_backend.services.restore_lease import MongoRestoreLeaseStore, has_active_restore

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_leases"
TTL = timedelta(minutes=15)

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreLease, RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def test_one_holder_per_organization() -> None:
    store = MongoRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()

    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.acquire(organization, second, ttl=TTL) is False
    assert await store.acquire(organization, first, ttl=TTL) is True
    assert await store.renew(organization, second, ttl=TTL) is False
    assert await store.renew(organization, first, ttl=TTL) is True
    await store.release(organization, second)
    assert await store.acquire(organization, second, ttl=TTL) is False
    await store.release(organization, first)
    assert await store.acquire(organization, second, ttl=TTL) is True


async def test_an_expired_lease_can_be_taken_over() -> None:
    store = MongoRestoreLeaseStore()
    organization, first, second = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    await store.acquire(organization, first, ttl=-timedelta(seconds=1))

    assert await store.acquire(organization, second, ttl=TTL) is True
    assert await store.renew(organization, first, ttl=TTL) is False
    await store.release(organization, first)
    assert await store.acquire(organization, first, ttl=TTL) is False


async def test_concurrent_acquisitions_admit_exactly_one_holder() -> None:
    store = MongoRestoreLeaseStore()
    organization = PydanticObjectId()
    contenders = [PydanticObjectId() for _ in range(12)]

    won = await asyncio.gather(*(store.acquire(organization, contender, ttl=TTL) for contender in contenders))

    assert won.count(True) == 1
    holder = contenders[won.index(True)]
    stored = await RestoreLease.get_pymongo_collection().find({"organization_id": organization}).to_list()
    assert [lease["holder_operation_id"] for lease in stored] == [holder]


async def test_abandoned_leases_expire_and_organizations_are_unique() -> None:
    indexes = await RestoreLease.get_pymongo_collection().index_information()

    assert indexes["restore_lease_expiry"]["expireAfterSeconds"] == 0
    assert indexes["restore_lease_organization_unique"]["unique"] is True


async def test_active_restores_are_other_queued_or_running_operations() -> None:
    organization = PydanticObjectId()
    queued = RestoreOperation(
        organization_id=organization,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.QUEUED,
    )
    await queued.insert()
    assert queued.id is not None

    assert await has_active_restore(organization, queued.id) is False
    assert await has_active_restore(organization, PydanticObjectId()) is True
    assert await has_active_restore(PydanticObjectId(), PydanticObjectId()) is False

    queued.status = RestoreStatus.COMPLETED
    await queued.save()
    assert await has_active_restore(organization, PydanticObjectId()) is False


async def test_a_live_lease_of_another_restore_is_active_without_a_queued_operation() -> None:
    store = MongoRestoreLeaseStore()
    organization, holder, asking = PydanticObjectId(), PydanticObjectId(), PydanticObjectId()
    assert await has_active_restore(organization, asking) is False

    # The holder's worker died between its terminal persist and its release.
    await store.acquire(organization, holder, ttl=TTL)

    assert await store.held_by_another(organization, asking) is True
    assert await store.held_by_another(organization, holder) is False
    assert await has_active_restore(organization, asking) is True
    assert await has_active_restore(organization, holder) is False

    await store.release(organization, holder)
    await store.acquire(organization, holder, ttl=-timedelta(seconds=1))
    assert await store.held_by_another(organization, asking) is False
    assert await has_active_restore(organization, asking) is False
