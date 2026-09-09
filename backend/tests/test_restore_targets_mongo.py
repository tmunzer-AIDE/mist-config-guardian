"""Database-backed checks that the rest of the suite cannot make.

Parity between the MongoDB target search and the Python reference.

The rest of the suite runs with no database, so the aggregation that a
deployment actually executes is never exercised there. This module runs both
implementations against the same real collections and requires them to agree:
the Python search in ``InMemoryRestoreTargetSearch`` is the specification, and
every assertion made about it elsewhere therefore also constrains the pipeline.

It is skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB, so it never
turns an ordinary ``make check`` red.
"""

import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.services.restore_targets import (
    InMemoryRestoreTargetSearch,
    MongoRestoreTargetReader,
    MongoRestoreTargetSearch,
    RestoreTargetQuery,
)

MONGO_URL = os.environ.get("MONGO_TEST_URL")

# The client binds to the loop it was created on, so the seeded database and
# every test that reads it share one module-scoped loop.
pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("seeded"),
]

ORGANIZATION_ID = PydanticObjectId()
OTHER_ORGANIZATION_ID = PydanticObjectId()
OBSERVED_AT = datetime(2026, 2, 1, tzinfo=UTC)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def seeded() -> None:
    """Initialise a scratch database and fill it with the shared catalogue."""
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    database = client["restore_targets_parity"]
    await client.drop_database("restore_targets_parity")
    await init_beanie(database=database, document_models=[LogicalObject, ObjectVersion])

    catalogue = [
        ("Alpha", "sites", "org", None, "site-a", False, 3),
        ("Bravo", "sites", "org", None, "site-b", False, 2),
        ("Corp WLAN", "wlans", "site", "site-a", "mist-corp", False, 4),
        ("Guest WLAN", "wlans", "site", "site-b", "mist-guest", False, 1),
        # Deleted objects stay restorable: what a restore writes back is the
        # newest version that was not itself a deletion.
        ("Lab WLAN", "wlans", "site", "site-a", "mist-lab", True, 2),
        ("Corp network", "networks", "org", None, "mist-net", False, 5),
        # Present but with no restorable version at all.
        ("Ghost WLAN", "wlans", "site", "site-a", "mist-ghost", False, 0),
        # A site nothing names, so its facet row must not appear.
        ("Orphan site", "sites", "org", None, "site-z", False, 1),
    ]
    for name, object_type, scope, site_mist_id, mist_id, deleted, versions in catalogue:
        logical = LogicalObject(
            organization_id=ORGANIZATION_ID,
            scope=scope,
            object_type=object_type,
            source_key=name,
            current_mist_id=mist_id,
            site_mist_id=site_mist_id,
            name=name,
            is_deleted=deleted,
            current_version=versions,
        )
        await logical.insert()
        for version in range(1, versions + 1):
            await ObjectVersion(
                organization_id=ORGANIZATION_ID,
                logical_object_id=logical.id,
                incarnation_id=PydanticObjectId(),
                version=version,
                event=VersionEvent.INITIAL if version == 1 else VersionEvent.UPDATED,
                configuration={"name": name},
                configuration_hash=f"{name}-{version}",
                is_deleted=False,
                observed_at=OBSERVED_AT,
            ).insert()
        if deleted:
            # The deletion is the newest version and must not be the one offered.
            await ObjectVersion(
                organization_id=ORGANIZATION_ID,
                logical_object_id=logical.id,
                incarnation_id=PydanticObjectId(),
                version=versions + 1,
                event=VersionEvent.DELETED,
                configuration={},
                configuration_hash=f"{name}-gone",
                is_deleted=True,
                observed_at=OBSERVED_AT,
            ).insert()

    # Another organization's object, which must never be reachable from this one.
    foreign = LogicalObject(
        organization_id=OTHER_ORGANIZATION_ID,
        scope="site",
        object_type="wlans",
        source_key="Foreign",
        current_mist_id="mist-foreign",
        site_mist_id="site-a",
        name="Foreign",
        current_version=1,
    )
    await foreign.insert()
    await ObjectVersion(
        organization_id=OTHER_ORGANIZATION_ID,
        logical_object_id=foreign.id,
        incarnation_id=PydanticObjectId(),
        version=1,
        event=VersionEvent.INITIAL,
        configuration={},
        configuration_hash="foreign-1",
        is_deleted=False,
        observed_at=OBSERVED_AT,
    ).insert()

    yield
    await client.drop_database("restore_targets_parity")
    await client.close()


QUERIES = [
    RestoreTargetQuery(organization_id=ORGANIZATION_ID),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, scope="org"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, scope="site"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, q="corp"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, q="WLANS"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, q="."),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, site_id="site-a"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, object_type="wlans"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, object_type="wlans", site_id="site-a"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, scope="site", object_type="wlans", q="wlan"),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, skip=1, limit=2),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, skip=4, limit=3),
    RestoreTargetQuery(organization_id=ORGANIZATION_ID, skip=99, limit=10),
    RestoreTargetQuery(organization_id=OTHER_ORGANIZATION_ID),
]


@pytest.mark.parametrize("query", QUERIES, ids=lambda q: f"{q.scope}-{q.object_type}-{q.site_id}-{q.q}-{q.skip}")
async def test_pipeline_matches_the_python_reference(query: RestoreTargetQuery) -> None:
    reference = await InMemoryRestoreTargetSearch(MongoRestoreTargetReader()).search(query)
    pipeline = await MongoRestoreTargetSearch().search(query)

    assert pipeline.total == reference.total
    assert pipeline.types == reference.types
    assert pipeline.sites == reference.sites
    assert [item.name for item in pipeline.items] == [item.name for item in reference.items]
    assert pipeline.items == reference.items


async def test_the_catalogue_is_not_trivially_empty() -> None:
    """Guard the parity assertions above from passing on an empty database."""
    page = await MongoRestoreTargetSearch().search(RestoreTargetQuery(organization_id=ORGANIZATION_ID))

    assert page.total == 7
    assert "Ghost WLAN" not in {item.name for item in page.items}
    # The deletion is newest, but version 2 is what a restore would write back.
    lab = next(item for item in page.items if item.name == "Lab WLAN")
    assert lab.version == 2
    assert lab.site_name == "Alpha"


# ------------------------------------------------------- single object lookup
async def test_an_object_is_readable_on_its_own() -> None:
    """The history panel resolves a selection its page does not contain."""
    logical = await LogicalObject.find_one(
        LogicalObject.organization_id == ORGANIZATION_ID,
        LogicalObject.name == "Corp WLAN",
    )
    assert logical is not None

    found = await LogicalObject.find_one(
        LogicalObject.id == logical.id,
        LogicalObject.organization_id == ORGANIZATION_ID,
    )

    assert found is not None
    assert found.name == "Corp WLAN"


async def test_an_object_is_not_readable_from_another_organization() -> None:
    """The id alone must never be enough; both conditions are load-bearing."""
    logical = await LogicalObject.find_one(
        LogicalObject.organization_id == ORGANIZATION_ID,
        LogicalObject.name == "Corp WLAN",
    )
    assert logical is not None

    leaked = await LogicalObject.find_one(
        LogicalObject.id == logical.id,
        LogicalObject.organization_id == OTHER_ORGANIZATION_ID,
    )

    assert leaked is None
