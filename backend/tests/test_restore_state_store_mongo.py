"""The compensation lookup returns the newest attempt.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreOperationStateRecord
from mist_config_guardian_backend.services.restore_planner import MongoRestoreStateStore

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_state_store"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[RestoreOperationStateRecord])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def _compensation(
    organization: PydanticObjectId, source: PydanticObjectId, *, age: timedelta
) -> PydanticObjectId:
    identifier = PydanticObjectId()
    await RestoreOperationStateRecord(
        organization_id=organization,
        operation_id=identifier,
        plan_hash="hash",
        compensates_operation_id=source,
        created_at=datetime.now(UTC) - age,
    ).insert()
    return identifier


async def test_without_a_pointer_the_newest_compensation_is_returned() -> None:
    organization, source = PydanticObjectId(), PydanticObjectId()
    oldest = await _compensation(organization, source, age=timedelta(hours=2))
    newest = await _compensation(organization, source, age=timedelta(minutes=1))
    middle = await _compensation(organization, source, age=timedelta(hours=1))
    store = MongoRestoreStateStore()

    found = await store.find_compensation_of(organization, source)

    assert found is not None
    assert found.operation_id == newest
    assert [state.operation_id for state in await store.compensations_of(organization, source)] == [
        oldest,
        middle,
        newest,
    ]


async def test_the_source_pointer_wins() -> None:
    organization, source = PydanticObjectId(), PydanticObjectId()
    pointed = await _compensation(organization, source, age=timedelta(hours=2))
    await _compensation(organization, source, age=timedelta(minutes=1))
    await RestoreOperationStateRecord(
        organization_id=organization, operation_id=source, plan_hash="source", compensation_operation_id=pointed
    ).insert()

    found = await MongoRestoreStateStore().find_compensation_of(organization, source)

    assert found is not None
    assert found.operation_id == pointed


async def test_compensations_of_another_organization_are_not_returned() -> None:
    organization, source = PydanticObjectId(), PydanticObjectId()
    await _compensation(PydanticObjectId(), source, age=timedelta(minutes=1))
    store = MongoRestoreStateStore()

    assert await store.find_compensation_of(organization, source) is None
    assert await store.compensations_of(organization, source) == []
