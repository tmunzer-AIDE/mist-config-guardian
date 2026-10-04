"""Database-backed checks of the time bar's marker query.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.webhook import AuditChangeGroup, ChangedObjectRef
from mist_config_guardian_backend.services.point_in_time import BeaniePointInTimeReader

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "point_in_time_markers"
WINDOW_START = datetime(2026, 9, 1, tzinfo=UTC)

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[AuditChangeGroup])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def _group(organization_id: PydanticObjectId, hour: int, *, captured: bool = True) -> None:
    await AuditChangeGroup(
        organization_id=organization_id,
        audit_id=f"audit-{hour}",
        occurred_at=WINDOW_START + timedelta(hours=hour),
        changed_objects=(
            [
                ChangedObjectRef(
                    logical_object_id=PydanticObjectId(),
                    object_type="wlans",
                    object_name="Corp-WLAN",
                    scope="org",
                    event="updated",
                )
            ]
            if captured
            else []
        ),
    ).insert()


async def test_a_crowded_window_keeps_its_newest_markers_oldest_first() -> None:
    organization_id = PydanticObjectId()
    for hour in range(1, 6):
        await _group(organization_id, hour)

    markers = await BeaniePointInTimeReader().markers(
        organization_id,
        start=WINDOW_START,
        end=WINDOW_START + timedelta(days=1),
        limit=3,
    )

    assert [group.audit_id for group in markers] == ["audit-3", "audit-4", "audit-5"]


async def test_groups_with_no_captured_difference_do_not_use_up_the_markers() -> None:
    """A receipt alone is not a change: the feed hides such groups, so the time bar does too."""
    organization_id = PydanticObjectId()
    await _group(organization_id, 1, captured=False)
    await _group(organization_id, 2)
    await _group(organization_id, 3)
    await _group(organization_id, 4, captured=False)

    markers = await BeaniePointInTimeReader().markers(
        organization_id,
        start=WINDOW_START,
        end=WINDOW_START + timedelta(days=1),
        limit=2,
    )

    assert [group.audit_id for group in markers] == ["audit-2", "audit-3"]
