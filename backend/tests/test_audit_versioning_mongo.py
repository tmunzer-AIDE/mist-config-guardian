"""Database-backed checks of what an audit webhook records against stored objects.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from collections.abc import Callable
from types import TracebackType
from typing import Self
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion, VersionEvent
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import audit_versioning
from mist_config_guardian_backend.services.audit_versioning import AuditVersioningService
from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "audit_versioning_records"

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


def _definition(scope: str, object_type: str) -> ObjectDefinition:
    definition = get_definition(scope, object_type)
    assert definition is not None
    return definition


async def _capture(
    organization_id: PydanticObjectId,
    scope: str,
    object_type: str,
    configuration: dict[str, object],
    *,
    site_id: str | None = None,
) -> LogicalObject:
    await SnapshotService(_vault()).capture_configuration(
        organization_id,
        _definition(scope, object_type),
        configuration,
        CaptureContext(snapshot_id=None, site_id=site_id),
    )
    logical = await LogicalObject.find_one(
        LogicalObject.organization_id == organization_id,
        LogicalObject.current_mist_id == configuration["id"],
    )
    assert logical is not None
    return logical


async def _apply(organization_id: PydanticObjectId, payload: dict[str, object]) -> None:
    receipt = WebhookReceipt.model_construct(organization_id=organization_id, topic="audits", audit_id="audit-1")
    organization = Organization.model_construct(id=organization_id, mist_org_id="org-1")
    await AuditVersioningService(_vault()).apply(receipt, payload, organization)


async def _deleted(logical: LogicalObject) -> bool:
    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    return stored.is_deleted


async def _events(logical: LogicalObject) -> list[tuple[int, VersionEvent]]:
    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    return [(version.version, version.event) for version in versions]


# -- deletes Mist names only by name -----------------------------------------------------------------------------------


async def test_a_name_only_delete_tombstones_only_its_own_site() -> None:
    """Mist sends ``"wlan_id": "None"`` on a delete; the name is all that is left, and names repeat across sites."""
    organization_id = PydanticObjectId()
    # Site B's "Guest" is stored first, so an unscoped lookup finds it first.
    site_b = await _capture(organization_id, "site", "wlans", {"id": "wlan-b", "ssid": "Guest"}, site_id="site-b")
    site_z = await _capture(organization_id, "site", "wlans", {"id": "wlan-z", "ssid": "Guest"}, site_id="site-z")

    await _apply(organization_id, {"site_id": "site-z", "wlan_id": "None", "message": 'Delete WLAN "Guest"'})

    assert (await _deleted(site_z), await _deleted(site_b)) == (True, False)


async def test_a_name_only_delete_matching_two_live_objects_tombstones_neither() -> None:
    organization_id = PydanticObjectId()
    first = await _capture(organization_id, "site", "wlans", {"id": "wlan-1", "ssid": "Guest"}, site_id="site-z")
    second = await _capture(organization_id, "site", "wlans", {"id": "wlan-2", "ssid": "Guest"}, site_id="site-z")

    await _apply(organization_id, {"site_id": "site-z", "wlan_id": "None", "message": 'Delete WLAN "Guest"'})

    # Either guess could delete the one still in use; the next backup settles it.
    assert (await _deleted(first), await _deleted(second)) == (False, False)


# -- a deletion racing another writer ----------------------------------------------------------------------------------


def _race_before_tombstone(
    monkeypatch: pytest.MonkeyPatch, competitor: Callable[[ObjectVersion], ObjectVersion]
) -> None:
    """Have another writer append ``competitor(tombstone)`` between the tombstone's read and its insert."""
    insert = ObjectVersion.insert
    raced = False

    async def insert_after_another_writer(self: ObjectVersion, *args: object, **kwargs: object) -> ObjectVersion:
        nonlocal raced
        if self.is_deleted and not raced:
            raced = True
            await insert(competitor(self))
        return await insert(self, *args, **kwargs)

    monkeypatch.setattr(ObjectVersion, "insert", insert_after_another_writer)


async def test_a_tombstone_that_loses_its_version_number_to_a_capture_is_appended_after_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    logical = await _capture(organization_id, "org", "networks", {"id": "net-1", "name": "Corp", "vlan_id": 1})
    _race_before_tombstone(
        monkeypatch,
        lambda tombstone: tombstone.model_copy(
            update={"id": None, "event": VersionEvent.UPDATED, "is_deleted": False, "audit_id": "other"}
        ),
    )

    await _apply(organization_id, {"network_id": "net-1", "message": 'Delete Network "Corp"'})

    assert await _events(logical) == [(1, VersionEvent.INITIAL), (2, VersionEvent.UPDATED), (3, VersionEvent.DELETED)]
    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert (stored.is_deleted, stored.current_version) == (True, 3)


async def test_a_deletion_another_writer_already_recorded_is_not_recorded_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    logical = await _capture(organization_id, "org", "networks", {"id": "net-2", "name": "Lab", "vlan_id": 1})
    _race_before_tombstone(monkeypatch, lambda tombstone: tombstone.model_copy(update={"id": None}))

    await _apply(organization_id, {"network_id": "net-2", "message": 'Delete Network "Lab"'})

    assert await _events(logical) == [(1, VersionEvent.INITIAL), (2, VersionEvent.DELETED)]
    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert (stored.is_deleted, stored.current_version) == (True, 2)


# -- device profiles ---------------------------------------------------------------------------------------------------


class _DeviceProfiles:
    """Mist's device-profile collection, which answers one profile type per request."""

    def __init__(self, profiles: list[dict[str, object]]) -> None:
        self._profiles = profiles

    def __call__(self, **_kwargs: object) -> Self:
        return self

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self, _type: type[BaseException] | None, _value: BaseException | None, _traceback: TracebackType | None
    ) -> None:
        return None

    async def fetch(self, definition: ObjectDefinition, **_kwargs: object) -> list[dict[str, object]]:
        requested = dict(definition.request_params).get("type")
        return [profile for profile in self._profiles if profile["type"] == requested]


async def test_a_switch_profile_update_is_recorded_as_a_switch_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mist audits every device profile as ``deviceprofile``, whatever type it is."""
    organization_id = PydanticObjectId()
    profiles = _DeviceProfiles(
        [
            {"id": "ap-profile", "type": "ap", "name": "AP"},
            {"id": "switch-profile", "type": "switch", "name": "Access", "port_config": {}},
        ]
    )
    monkeypatch.setattr(audit_versioning, "service_token", AsyncMock(return_value="token"))
    monkeypatch.setattr(audit_versioning, "MistConfigurationClient", profiles)

    await _apply(organization_id, {"deviceprofile_id": "switch-profile", "message": 'Update Device Profile "Access"'})

    recorded = await LogicalObject.find(LogicalObject.organization_id == organization_id).to_list()
    assert [(item.object_type, item.current_mist_id) for item in recorded] == [("switchprofiles", "switch-profile")]
    version = await ObjectVersion.find_one(ObjectVersion.logical_object_id == recorded[0].id)
    assert version is not None
    assert version.audit_id == "audit-1"


async def test_a_gateway_profile_delete_tombstones_the_gateway_profile() -> None:
    organization_id = PydanticObjectId()
    logical = await _capture(
        organization_id, "org", "hubprofiles", {"id": "hub-profile", "type": "gateway", "name": "Hub"}
    )

    await _apply(organization_id, {"deviceprofile_id": "hub-profile", "message": 'Delete Device Profile "Hub"'})

    assert await _deleted(logical)
