"""Real MongoDB coverage for site event pagination, isolation and immutable inventory.

Runs only against MONGO_TEST_URL; uses a unique scratch database per test.
"""

import os
from datetime import timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import MonitoringSession, MonitoringTimelineEvent, SleObservation
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectVersion
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, ChangedObjectRef
from mist_config_guardian_backend.services import site_impact

MONGO_URL = os.environ.get("MONGO_TEST_URL")
pytestmark = pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set")
SITE = "d6fb4f96-3ba4-4cf5-8af2-a8d7b85087ac"
OTHER_SITE = "11111111-1111-1111-1111-111111111111"


@pytest_asyncio.fixture
async def inventory():
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    database_name = f"guardian_site_impact_test_{uuid4().hex}"
    await init_beanie(
        client[database_name], document_models=[LogicalObject, ObjectVersion, MonitoringSession, AuditChangeGroup]
    )
    org, other = PydanticObjectId(), PydanticObjectId()
    now = utc_now().replace(microsecond=0)
    for owner, site, name in [(org, SITE, "Paris"), (org, OTHER_SITE, "London"), (other, SITE, "Other tenant")]:
        await LogicalObject(
            organization_id=owner,
            scope="org",
            object_type="sites",
            source_key=site,
            current_mist_id=site,
            name=name,
            created_at=now - timedelta(days=2),
        ).insert()
    try:
        yield org, other, now
    finally:
        await client.drop_database(database_name)
        await client.close()


async def seed_window(org, site, now, *, mac="aabbccddeeff", audits=None):
    return await MonitoringSession(
        organization_id=org,
        site_id=site,
        device_mac=mac,
        device_name=f"Switch {mac}",
        device_type="switch",
        audit_ids=audits if audits is not None else ["template"],
        active=False,
        status="completed",
        created_at=now - timedelta(minutes=10),
        change_triggered_at=now - timedelta(minutes=10),
        config_applied_at=now - timedelta(minutes=9),
        monitoring_started_at=now - timedelta(minutes=10),
        monitoring_ends_at=now + timedelta(minutes=50),
        baseline=SleObservation(
            captured_at=now - timedelta(minutes=10), scope="device", values={"switch-throughput": 99}
        ),
        observations=[
            SleObservation(captured_at=now - timedelta(minutes=1), scope="device", values={"switch-throughput": 98}),
            SleObservation(captured_at=now + timedelta(hours=1), scope="device", values={"switch-throughput": 20}),
        ],
        timeline=[
            MonitoringTimelineEvent(
                key="received",
                event_type="SW_CONFIG_CHANGED_BY_USER",
                occurred_at=now - timedelta(minutes=10),
                received_at=now - timedelta(minutes=10),
                audit_id="template",
            )
        ],
    ).insert()


async def test_real_event_pagination_expands_one_site_and_retains_uncorrelated_changes(inventory):
    org, other, now = inventory
    group = await AuditChangeGroup(
        organization_id=org,
        audit_id="template",
        affected_site_ids=[SITE, OTHER_SITE],
        created_at=now - timedelta(minutes=20),
        occurred_at=now - timedelta(minutes=20),
        changed_objects=[
            ChangedObjectRef(
                logical_object_id=PydanticObjectId(),
                object_type="networktemplates",
                object_name="Access policy",
                scope="org",
                event="updated",
            )
        ],
    ).insert()
    await AuditChangeGroup(
        organization_id=other,
        audit_id="template",
        affected_site_ids=[SITE],
        created_at=now - timedelta(minutes=20),
        message="OTHER TENANT",
    ).insert()
    await seed_window(org, SITE, now)
    await seed_window(org, SITE, now, mac="112233445566")
    await seed_window(org, OTHER_SITE, now, mac="abcdefabcdef")
    await seed_window(other, SITE, now, mac="abababababab")
    orphan = await seed_window(org, SITE, now, mac="121212121212", audits=[])
    first = await site_impact.list_changes(org, SITE, range_key="24h", end=None, skip=0, limit=1)
    assert first.total == 2
    assert first.items[0].id == f"session:{orphan.id}"
    assert len(first.items[0].impacts) == 1
    second = await site_impact.list_changes(org, SITE, range_key="24h", end=None, skip=1, limit=1)
    assert second.items[0].id == str(group.id)
    assert {item.device_id for item in second.items[0].impacts} == {"aabbccddeeff", "112233445566"}
    assert all(item.metrics[0].latest == 98 for item in second.items[0].impacts)
    assert "Access policy" in second.items[0].title
    assert "OTHER TENANT" not in second.model_dump_json()
    sites = await site_impact.list_sites(org, now)
    assert {item.name for item in sites.items} == {"Paris", "London"}


async def test_history_drops_late_arrivals_and_withholds_mutable_verdicts(inventory):
    org, _other, now = inventory
    await AuditChangeGroup(
        organization_id=org,
        audit_id="template",
        affected_site_ids=[SITE],
        created_at=now - timedelta(minutes=20),
        occurred_at=now - timedelta(minutes=20),
    ).insert()
    await AuditChangeGroup(
        organization_id=org,
        audit_id="late",
        affected_site_ids=[SITE],
        created_at=now + timedelta(minutes=5),
        occurred_at=now - timedelta(minutes=1),
    ).insert()
    await seed_window(org, SITE, now)
    result = await site_impact.list_changes(org, SITE, range_key="24h", end=now, skip=0, limit=50)
    assert result.total == 1
    assert len(result.items[0].impacts) == 1
    evidence = result.items[0].impacts[0]
    assert evidence.severity == "unknown"
    assert evidence.metrics == []
    assert evidence.observation_count == 1


async def test_stored_topology_uses_the_last_version_before_the_cutoff(inventory):
    org, other, now = inventory
    for owner, site, mac in [
        (org, SITE, "aabbccddeeff"),
        (org, OTHER_SITE, "112233445566"),
        (other, SITE, "abababababab"),
    ]:
        device = await LogicalObject(
            organization_id=owner,
            scope="site",
            object_type="devices",
            site_mist_id=site,
            source_key=mac,
            current_mist_id=mac,
            name="CURRENT NAME",
            created_at=now - timedelta(days=1),
        ).insert()
        for version, at, name in [(1, now - timedelta(hours=1), "Before"), (2, now + timedelta(hours=1), "Future")]:
            await ObjectVersion(
                organization_id=owner,
                logical_object_id=device.id,
                incarnation_id=PydanticObjectId(),
                version=version,
                event="updated",
                configuration={"mac": mac, "type": "switch", "name": name, "secret": "DO NOT RETURN"},
                configuration_hash=str(version),
                observed_at=at,
            ).insert()
    topology = await site_impact.stored_topology(org, SITE, now, historical=True)
    assert len(topology.devices) == 1
    assert topology.devices[0].name == "Before"
    assert topology.devices[0].health == "unknown"
    assert "DO NOT RETURN" not in topology.model_dump_json()
