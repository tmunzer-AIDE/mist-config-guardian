"""Database-backed checks of what the executor records after a Mist write.

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
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion, VersionEvent
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import restore_executor
from mist_config_guardian_backend.services.restore_executor import RestoreExecutor
from mist_config_guardian_backend.snapshots.registry import get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_executor_records"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[LogicalObject, ObjectIncarnation, ObjectVersion])
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


async def _deleted_object(
    *,
    object_type: str = "networks",
    scope: str = "org",
    mist_id: str = "old-network",
    site_mist_id: str | None = None,
    configuration: dict[str, object] | None = None,
) -> LogicalObject:
    """Seed an object that was captured once and then deleted."""
    organization_id = PydanticObjectId()
    logical = LogicalObject(
        organization_id=organization_id,
        scope=scope,
        object_type=object_type,
        source_key=f"{site_mist_id or 'org'}:{object_type}:{mist_id}",
        current_mist_id=mist_id,
        site_mist_id=site_mist_id,
        name="Corp",
        is_deleted=True,
        current_version=2,
    )
    await logical.insert()
    incarnation = ObjectIncarnation(
        organization_id=organization_id,
        logical_object_id=logical.id,
        mist_object_id=mist_id,
        site_mist_id=site_mist_id,
        ordinal=1,
        ended_at=datetime.now(UTC),
    )
    await incarnation.insert()
    stored = configuration or {"id": mist_id, "name": "Corp"}
    for number, deleted in ((1, False), (2, True)):
        await ObjectVersion(
            organization_id=organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            version=number,
            event=VersionEvent.DELETED if deleted else VersionEvent.INITIAL,
            configuration=stored,
            configuration_hash=f"hash-{number}",
            is_deleted=deleted,
        ).insert()
    return logical


def _operation_for(
    logical: LogicalObject,
    *,
    action_type: RestoreActionType = RestoreActionType.CREATE,
    resulting_mist_id: str | None = "new-network",
) -> tuple[RestoreOperation, RestoreAction]:
    action = RestoreAction(
        logical_object_id=logical.id,
        source_version_id=PydanticObjectId(),
        order=0,
        action=action_type,
        scope=logical.scope,
        object_type=logical.object_type,
        object_name=logical.name,
        current_mist_id=logical.current_mist_id,
        site_mist_id=logical.site_mist_id,
        protected_configuration={"name": "Corp"},
        status=RestoreActionStatus.COMPLETED,
        resulting_mist_id=resulting_mist_id,
    )
    operation = RestoreOperation.model_construct(
        id=PydanticObjectId(),
        organization_id=logical.organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
        requested_version_ids=[],
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.RUNNING,
        actions=[action],
        warnings=[],
        preflight_errors=[],
        credential_actor="admin@example.com",
        started_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    return operation, action


async def test_a_version_number_taken_by_a_concurrent_tombstone_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    real_latest = restore_executor.latest_version
    raced = False

    async def _racing_latest(logical_id):
        nonlocal raced
        latest = await real_latest(logical_id)
        if not raced and latest is not None:
            raced = True
            await ObjectVersion(
                organization_id=latest.organization_id,
                logical_object_id=latest.logical_object_id,
                incarnation_id=latest.incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.DELETED,
                configuration=latest.configuration,
                configuration_hash=latest.configuration_hash,
                is_deleted=True,
            ).insert()
        return latest

    monkeypatch.setattr(restore_executor, "latest_version", _racing_latest)
    definition = get_definition("org", "networks")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition.sensitive_fields, {"name": "Corp"}, site_id=None
    )

    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    assert [(version.version, version.event) for version in versions] == [
        (1, VersionEvent.INITIAL),
        (2, VersionEvent.DELETED),
        (3, VersionEvent.DELETED),
        (4, VersionEvent.RESTORED),
    ]
