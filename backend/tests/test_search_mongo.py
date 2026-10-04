"""Database-backed checks of the global search lookups.

The service tests run against an in-memory reader, which cannot catch a filter
the database answers differently. Skipped unless ``MONGO_TEST_URL`` names a
reachable MongoDB.
"""

import os

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.models.snapshot import LogicalObject
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, ChangedObjectRef
from mist_config_guardian_backend.services.search import BeanieSearchReader

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "search_reader_records"

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
        document_models=[AuditChangeGroup, LogicalObject, RestoreOperation],
    )
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def test_object_search_finds_a_stored_object() -> None:
    organization_id = PydanticObjectId()
    await LogicalObject(
        organization_id=organization_id,
        scope="org",
        object_type="wlans",
        source_key="org:wlans:w1",
        current_mist_id="w1",
        name="Corp-WLAN",
        current_version=1,
    ).insert()

    found = await BeanieSearchReader().objects(organization_id, "Corp", limit=10)

    assert [item.name for item in found] == ["Corp-WLAN"]


async def test_change_group_search_skips_groups_with_no_captured_difference() -> None:
    """A receipt alone is not a change: the feed hides such groups, so search does too."""
    organization_id = PydanticObjectId()
    await AuditChangeGroup(
        organization_id=organization_id,
        audit_id="audit-captured",
        actor="j.mercer",
        changed_objects=[
            ChangedObjectRef(
                logical_object_id=PydanticObjectId(),
                object_type="wlans",
                object_name="Corp-WLAN",
                scope="org",
                event="updated",
            )
        ],
    ).insert()
    await AuditChangeGroup(organization_id=organization_id, audit_id="audit-receipt-only", actor="j.mercer").insert()

    found = await BeanieSearchReader().change_groups(organization_id, "mercer", limit=10)

    assert [group.audit_id for group in found] == ["audit-captured"]
