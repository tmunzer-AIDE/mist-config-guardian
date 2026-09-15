"""The compensation lookup returns the newest attempt, and a stale plan is retired atomically.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import (
    RestoreMode,
    RestoreOperation,
    RestoreOperationStateRecord,
    RestoreStatus,
)
from mist_config_guardian_backend.services.restore_planner import BeanieRestorePlanRepository, MongoRestoreStateStore

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
    await init_beanie(database=client[DATABASE], document_models=[RestoreOperationStateRecord, RestoreOperation])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def _plan(organization: PydanticObjectId, **fields: object) -> RestoreOperation:
    plan = RestoreOperation(
        organization_id=organization,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime.now(UTC),
        **fields,
    )
    return await plan.insert()


async def test_only_a_planned_compensation_that_never_started_is_retired() -> None:
    organization, replacement = PydanticObjectId(), PydanticObjectId()
    stale = await _plan(
        organization, encrypted_delegated_credential="v1:held", delegated_credential_expires_at=datetime.now(UTC)
    )
    started = await _plan(organization, started_at=datetime.now(UTC))
    queued = await _plan(organization, status=RestoreStatus.QUEUED)
    elsewhere = await _plan(PydanticObjectId())
    plans = BeanieRestorePlanRepository()
    assert stale.id is not None
    assert started.id is not None
    assert queued.id is not None
    assert elsewhere.id is not None

    assert await plans.supersede_planned(organization, stale.id, replacement) is True
    assert await plans.supersede_planned(organization, stale.id, PydanticObjectId()) is False
    assert await plans.supersede_planned(organization, started.id, replacement) is False
    assert await plans.supersede_planned(organization, queued.id, replacement) is False
    assert await plans.supersede_planned(organization, elsewhere.id, replacement) is False

    retired = await RestoreOperation.get(stale.id)
    assert retired is not None
    assert retired.status is RestoreStatus.SUPERSEDED
    assert retired.superseded_by == replacement
    assert retired.encrypted_delegated_credential is None
    assert retired.delegated_credential_expires_at is None
    for untouched in (started, queued, elsewhere):
        reloaded = await RestoreOperation.get(untouched.id)
        assert reloaded is not None
        assert reloaded.status is untouched.status
        assert reloaded.superseded_by is None


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
