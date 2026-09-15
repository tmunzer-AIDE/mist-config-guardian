"""Database-backed checks of what the executor records after a Mist write.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist_mutation import MistMutationError
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionReason,
    RestoreActionStatus,
    RestoreActionType,
    RestoreMode,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import LogicalObject, ObjectIncarnation, ObjectVersion, VersionEvent
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services import restore_executor
from mist_config_guardian_backend.services.restore_compensation import RestoreCompensationService
from mist_config_guardian_backend.services.restore_executor import RestoreExecutor
from mist_config_guardian_backend.services.restore_identity import RestoreIdentityConflictError
from mist_config_guardian_backend.services.restore_planner import RestorePlanner
from mist_config_guardian_backend.services.restore_verification import RestoreVerificationService
from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
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
    await init_beanie(
        database=client[DATABASE],
        document_models=[LogicalObject, ObjectIncarnation, ObjectVersion, RestoreOperation],
    )
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


async def _deleted_object(  # noqa: PLR0913 - each seeded fact is chosen by some test
    *,
    object_type: str = "networks",
    scope: str = "org",
    mist_id: str = "old-network",
    site_mist_id: str | None = None,
    configuration: dict[str, object] | None = None,
    organization_id: PydanticObjectId | None = None,
    name: str = "Corp",
) -> LogicalObject:
    """Seed an object that was captured once and then deleted."""
    organization_id = organization_id or PydanticObjectId()
    logical = LogicalObject(
        organization_id=organization_id,
        scope=scope,
        object_type=object_type,
        source_key=f"{site_mist_id or 'org'}:{object_type}:{mist_id}",
        current_mist_id=mist_id,
        site_mist_id=site_mist_id,
        name=name,
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
    stored = configuration or {"id": mist_id, "name": name}
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
        operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
    )

    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    assert [(version.version, version.event) for version in versions] == [
        (1, VersionEvent.INITIAL),
        (2, VersionEvent.DELETED),
        (3, VersionEvent.DELETED),
        (4, VersionEvent.RESTORED),
    ]


# ------------------------------------------------------------------ identity


async def test_a_recreated_object_keeps_the_identity_the_collector_looks_for() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    definition = get_definition("org", "networks")
    assert definition is not None
    live = {"id": "new-network", "name": "Corp", "org_id": "org-1"}

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback=live, site_id=None
    )
    await SnapshotService(_vault()).capture_configuration(
        logical.organization_id, definition, dict(live), CaptureContext(snapshot_id=None, site_id=None)
    )

    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert stored.source_key == "org:networks:new-network"
    assert stored.current_mist_id == "new-network"
    assert stored.is_deleted is False
    assert await LogicalObject.find(LogicalObject.organization_id == logical.organization_id).count() == 1
    incarnations = (
        await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical.id).sort("ordinal").to_list()
    )
    assert [incarnation.mist_object_id for incarnation in incarnations] == ["old-network", "new-network"]


async def test_an_object_restored_under_a_recreated_site_moves_to_the_new_site() -> None:
    wlan = await _deleted_object(object_type="wlans", scope="site", mist_id="wlan-old", site_mist_id="site-old")
    operation, action = _operation_for(wlan, resulting_mist_id="wlan-new")
    definition = get_definition("site", "wlans")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation,
        action,
        definition,
        {"ssid": "Corp"},
        readback={"id": "wlan-new", "ssid": "Corp", "site_id": "site-new"},
        site_id="site-new",
    )

    stored = await LogicalObject.get(wlan.id)
    assert stored is not None
    assert stored.source_key == "site-new:wlans:wlan-new"
    assert stored.site_mist_id == "site-new"


async def test_site_settings_restored_under_a_recreated_site_are_rekeyed() -> None:
    settings = await _deleted_object(
        object_type="settings",
        scope="site",
        mist_id="site-old:settings",
        site_mist_id="site-old",
        configuration={"vlan": 5},
    )
    operation, action = _operation_for(
        settings, action_type=RestoreActionType.UPDATE, resulting_mist_id="site-old:settings"
    )
    definition = get_definition("site", "settings")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"vlan": 5}, readback={"vlan": 5, "site_id": "site-new"}, site_id="site-new"
    )

    stored = await LogicalObject.get(settings.id)
    assert stored is not None
    assert stored.source_key == "site-new:settings:site-new:settings"
    assert stored.current_mist_id == "site-new:settings"
    incarnations = (
        await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == settings.id).sort("ordinal").to_list()
    )
    assert [(item.ordinal, item.site_mist_id) for item in incarnations] == [(1, "site-old"), (2, "site-new")]


async def _captured_duplicate(logical: LogicalObject, *, created_at: datetime) -> LogicalObject:
    """What the webhook or a backup records for the new UUID before the executor re-keys."""
    duplicate = LogicalObject(
        organization_id=logical.organization_id,
        scope="org",
        object_type="networks",
        source_key="org:networks:new-network",
        current_mist_id="new-network",
        name="Corp",
        current_version=1,
        created_at=created_at,
    )
    await duplicate.insert()
    incarnation = ObjectIncarnation(
        organization_id=logical.organization_id,
        logical_object_id=duplicate.id,
        mist_object_id="new-network",
        ordinal=1,
    )
    await incarnation.insert()
    await ObjectVersion(
        organization_id=logical.organization_id,
        logical_object_id=duplicate.id,
        incarnation_id=incarnation.id,
        version=1,
        event=VersionEvent.CREATED,
        configuration={"id": "new-network", "name": "Corp"},
        configuration_hash="captured",
    ).insert()
    return duplicate


async def _assert_folded(logical: LogicalObject, duplicate: LogicalObject) -> None:
    assert await LogicalObject.get(duplicate.id) is None
    assert await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == duplicate.id).count() == 0
    assert await ObjectVersion.find(ObjectVersion.logical_object_id == duplicate.id).count() == 0
    versions = await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("version").to_list()
    assert [(version.version, version.event) for version in versions] == [
        (1, VersionEvent.INITIAL),
        (2, VersionEvent.DELETED),
        (3, VersionEvent.RESTORED),
        (4, VersionEvent.CREATED),
    ]
    assert versions[3].incarnation_id == versions[2].incarnation_id
    stored = await LogicalObject.get(logical.id)
    assert stored is not None
    assert stored.source_key == "org:networks:new-network"
    assert stored.current_version == 4


async def test_a_capture_that_raced_the_restore_is_folded_into_the_restored_identity() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    duplicate = await _captured_duplicate(logical, created_at=datetime.now(UTC))
    definition = get_definition("org", "networks")
    assert definition is not None

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
    )

    await _assert_folded(logical, duplicate)


async def test_a_capture_landing_between_the_lookup_and_the_rekey_is_caught_by_the_unique_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lookup finds no holder, the capture inserts one, and the real unique index refuses the re-key."""
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    definition = get_definition("org", "networks")
    assert definition is not None
    real_find_one = LogicalObject.find_one
    landed: list[LogicalObject] = []

    def _capture_lands_after_the_first_lookup(_cls, *args, **kwargs):
        # Only the holder lookup filters on four fields; ``get``, ``save`` and the re-key write address one id.
        if landed or len(args) != 4:
            return real_find_one(*args, **kwargs)

        async def _nothing_yet() -> None:
            landed.append(await _captured_duplicate(logical, created_at=datetime.now(UTC)))

        return _nothing_yet()

    # A classmethod, so Beanie's instance-level ``self.find_one`` binds the class as the original does.
    monkeypatch.setattr(LogicalObject, "find_one", classmethod(_capture_lands_after_the_first_lookup))

    await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
        operation, action, definition, {"name": "Corp"}, readback={"id": "new-network", "name": "Corp"}, site_id=None
    )

    monkeypatch.undo()
    assert len(landed) == 1
    await _assert_folded(logical, landed[0])


async def test_an_identity_older_than_the_restore_is_never_merged() -> None:
    logical = await _deleted_object()
    operation, action = _operation_for(logical)
    duplicate = await _captured_duplicate(logical, created_at=datetime.now(UTC) - timedelta(days=1))
    definition = get_definition("org", "networks")
    assert definition is not None

    with pytest.raises(RestoreIdentityConflictError, match="already owns") as raised:
        await RestoreExecutor(_vault())._record_result(  # noqa: SLF001
            operation,
            action,
            definition,
            {"name": "Corp"},
            readback={"id": "new-network", "name": "Corp"},
            site_id=None,
        )

    assert "new-network" not in str(raised.value)
    assert await LogicalObject.get(duplicate.id) is not None
    assert await ObjectVersion.find(ObjectVersion.logical_object_id == duplicate.id).count() == 1


# ---------------------------------------------------- a site and its settings


class _MemoryStateStore:
    """Plan-lifecycle state kept beside the run, keyed the way MongoDB keys it."""

    def __init__(self) -> None:
        self.items = {}

    async def load(self, organization_id, operation_id):
        return self.items.get((organization_id, operation_id))

    async def save(self, state):
        self.items[(state.organization_id, state.operation_id)] = state

    async def find_compensation_of(self, organization_id, operation_id):
        return next(
            (
                state
                for state in self.items.values()
                if state.organization_id == organization_id and state.compensates_operation_id == operation_id
            ),
            None,
        )


class _Notifications:
    def __init__(self) -> None:
        self.failed: list[str] = []
        self.completed: list[int] = []

    async def notify_restore_failed(self, *, organization_id, restore_id, reason, user_id=None):  # noqa: ARG002
        self.failed.append(reason)

    async def notify_restore_completed(self, *, organization_id, restore_id, applied_count, user_id=None):  # noqa: ARG002
        self.completed.append(applied_count)


class _MistAfterSiteDeletion:
    """Mist with a site and its settings gone; a recreated site comes back with default settings.

    Settings are a singleton at their site's path, so the id a call passes
    does not address them: only the site does.
    """

    def __init__(self, new_site_id: str) -> None:
        self.new_site_id = new_site_id
        self.sites: dict[str, dict[str, object]] = {}
        self.settings: dict[str, dict[str, object]] = {}
        self.writes: list[tuple[str, str | None]] = []
        self.reads: list[tuple[str, str, str | None]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return

    async def create(self, definition, configuration, *, org_id, site_id):
        assert definition.key == "sites"
        self.writes.append((definition.key, site_id))
        created = {**configuration, "id": self.new_site_id, "org_id": org_id}
        self.sites[self.new_site_id] = created
        self.settings[self.new_site_id] = {"site_id": self.new_site_id, "org_id": org_id}
        return dict(created)

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        assert definition.key == "settings"
        self.writes.append((definition.key, site_id))
        if site_id not in self.settings:
            msg = "Mist failed to update settings (404)"
            raise MistMutationError(msg)
        self.settings[site_id] = {**configuration, "site_id": site_id, "org_id": org_id}
        return dict(self.settings[site_id])

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        self.reads.append((definition.key, object_id, site_id))
        found = self.sites.get(object_id) if definition.key == "sites" else self.settings.get(site_id)
        return None if found is None else dict(found)


async def _site_and_settings_restore(organization_id: PydanticObjectId, old_site: str) -> RestoreOperation:
    """A queued plan recreating a deleted site and restoring its settings, as the planner builds it."""
    site = await _deleted_object(object_type="sites", mist_id=old_site, organization_id=organization_id, name="Lab")
    settings = await _deleted_object(
        object_type="settings",
        scope="site",
        mist_id=f"{old_site}:settings",
        site_mist_id=old_site,
        configuration={"vlan": 5, "site_id": old_site},
        organization_id=organization_id,
        name="Lab settings",
    )
    identifier = PydanticObjectId()
    operation = RestoreOperation(
        id=identifier,
        organization_id=organization_id,
        requested_by=PydanticObjectId(),
        mode=RestoreMode.NON_DESTRUCTIVE,
        target_at=datetime(2026, 1, 1, tzinfo=UTC),
        status=RestoreStatus.QUEUED,
        actions=[
            RestoreAction(
                logical_object_id=site.id,
                source_version_id=PydanticObjectId(),
                order=0,
                action=RestoreActionType.CREATE,
                scope="org",
                object_type="sites",
                object_name="Lab",
                current_mist_id=old_site,
                protected_configuration={"name": "Lab"},
            ),
            RestoreAction(
                logical_object_id=settings.id,
                source_version_id=PydanticObjectId(),
                order=1,
                action=RestoreActionType.UPDATE,
                scope="site",
                object_type="settings",
                object_name="Lab settings",
                current_mist_id=f"{old_site}:settings",
                site_mist_id=old_site,
                protected_configuration={"vlan": 5},
                expected_current_hash="plan-time-hash-of-the-deleted-site",
            ),
        ],
        credential_actor="admin@example.com",
        encrypted_delegated_credential=_vault().encrypt_for_context("api-token", context=f"restore:{identifier}"),
        delegated_credential_expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    await operation.insert()
    return operation


def _executor_against(
    monkeypatch: pytest.MonkeyPatch,
    client: "_MistAfterSiteDeletion | _MistAfterNetworkDeletion",
    organization_id: PydanticObjectId,
) -> tuple[RestoreExecutor, _MemoryStateStore, _Notifications, list[set[str]]]:
    """The real executor and verifier, with Mist, notifications and the worker queues faked."""
    monkeypatch.setattr(restore_executor, "MistMutationClient", lambda **_kwargs: client)

    async def _organization(*_args, **_kwargs) -> Organization:
        return Organization.model_construct(
            id=organization_id,
            mist_org_id="org-1",
            name="Lab",
            cloud_region=MistCloudRegion.GLOBAL_01,
            status=OrganizationStatus.VERIFIED,
        )

    monkeypatch.setattr(Organization, "get", _organization)
    reopened: list[set[str]] = []

    async def _reopen(_organization_id, site_ids):
        reopened.append(set(site_ids))
        return []

    store = _MemoryStateStore()
    notifications = _Notifications()
    verifier = RestoreVerificationService(
        store, queue_snapshot=lambda _organization_id: "snapshot-task", reopen_monitoring=_reopen
    )
    executor = RestoreExecutor(_vault(), store=store, notifications=notifications, verifier=verifier)
    return executor, store, notifications, reopened


async def test_a_deleted_site_restored_with_its_settings_is_verified_rekeyed_and_compensable_at_the_new_site(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id = PydanticObjectId()
    old_site, new_site = str(uuid4()), str(uuid4())
    operation = await _site_and_settings_restore(organization_id, old_site)
    identifier = operation.id
    assert identifier is not None
    client = _MistAfterSiteDeletion(new_site)
    executor, store, notifications, reopened = _executor_against(monkeypatch, client, organization_id)

    result = await executor.execute(identifier)

    assert notifications.failed == []
    assert result.status is RestoreStatus.COMPLETED
    ran = await RestoreOperation.get(identifier)
    assert ran is not None
    assert ran.status is RestoreStatus.COMPLETED
    assert [action.resulting_site_mist_id for action in ran.actions] == [None, new_site]
    assert client.writes == [("sites", None), ("settings", new_site)]
    state = await store.load(organization_id, identifier)
    assert state is not None
    assert state.verification is not None
    assert state.verification.verified is True
    # Verification reads last: the site, then the settings where they now live.
    assert client.reads[-2:] == [("sites", new_site, None), ("settings", f"{old_site}:settings", new_site)]
    assert all(site_id != old_site for _, _, site_id in client.reads)
    assert reopened == [{new_site}]

    restored_site = await LogicalObject.get(operation.actions[0].logical_object_id)
    restored_settings = await LogicalObject.get(operation.actions[1].logical_object_id)
    assert restored_site is not None
    assert restored_settings is not None
    assert restored_site.source_key == f"org:sites:{new_site}"
    assert restored_settings.source_key == f"{new_site}:settings:{new_site}:settings"
    assert restored_settings.current_mist_id == f"{new_site}:settings"
    assert restored_settings.site_mist_id == new_site
    assert restored_settings.is_deleted is False

    # The next backup finds both restored identities instead of starting new ones.
    snapshots = SnapshotService(_vault())
    sites_definition = get_definition("org", "sites")
    settings_definition = get_definition("site", "settings")
    assert sites_definition is not None
    assert settings_definition is not None
    await snapshots.capture_configuration(
        organization_id, sites_definition, client.sites[new_site], CaptureContext(snapshot_id=None, site_id=None)
    )
    await snapshots.capture_configuration(
        organization_id,
        settings_definition,
        client.settings[new_site],
        CaptureContext(snapshot_id=None, site_id=new_site),
    )
    assert await LogicalObject.find(LogicalObject.organization_id == organization_id).count() == 2

    # A completed run is not offered for compensation; reuse exactly what it
    # stored to show the reversal would target where the objects now live.
    ran.status = RestoreStatus.COMPENSATION_AVAILABLE
    plan = await RestoreCompensationService(store, _vault()).create_compensation_plan(
        operation=ran, requested_by=PydanticObjectId()
    )
    assert [
        (action.object_type, action.action, action.current_mist_id, action.site_mist_id) for action in plan.actions
    ] == [
        ("settings", RestoreActionType.UPDATE, f"{old_site}:settings", new_site),
        ("sites", RestoreActionType.DELETE, new_site, None),
    ]


# ------------------------------------- a recreated network and a WLAN pointing at it


class _MistAfterNetworkDeletion:
    """Mist with a network gone and a WLAN still referencing its UUID."""

    def __init__(self, new_network: str, wlan_id: str, live_wlan: dict[str, object]) -> None:
        self.new_network = new_network
        self.objects: dict[str, dict[str, object]] = {wlan_id: dict(live_wlan)}
        self.writes: list[tuple[str, str, dict[str, object]]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args: object) -> None:
        return

    async def create(self, definition, configuration, *, org_id, site_id):  # noqa: ARG002
        assert definition.key == "networks"
        self.writes.append(("create", definition.key, dict(configuration)))
        created = {**configuration, "id": self.new_network, "org_id": org_id}
        self.objects[self.new_network] = created
        return dict(created)

    async def update(self, definition, object_id, configuration, *, org_id, site_id):  # noqa: ARG002
        assert definition.key == "wlans"
        self.writes.append(("update", object_id, dict(configuration)))
        self.objects[object_id] = {**configuration, "id": object_id, "org_id": org_id}
        return dict(self.objects[object_id])

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        found = self.objects.get(object_id)
        return None if found is None else dict(found)


async def _wlan_referencing(
    organization_id: PydanticObjectId, network_id: str
) -> tuple[LogicalObject, list[ObjectVersion]]:
    """Seed a live WLAN with two captured versions, both referencing the network."""
    wlan_id = str(uuid4())
    wlan = LogicalObject(
        organization_id=organization_id,
        scope="org",
        object_type="wlans",
        source_key=f"org:wlans:{wlan_id}",
        current_mist_id=wlan_id,
        name="Corp WLAN",
        current_version=2,
    )
    await wlan.insert()
    incarnation = ObjectIncarnation(
        organization_id=organization_id, logical_object_id=wlan.id, mist_object_id=wlan_id, ordinal=1
    )
    await incarnation.insert()
    definition = get_definition("org", "wlans")
    assert definition is not None
    versions = []
    for number in (1, 2):
        configuration = {"id": wlan_id, "ssid": "Corp", "network_id": network_id, "vlan_id": number}
        version = ObjectVersion(
            organization_id=organization_id,
            logical_object_id=wlan.id,
            incarnation_id=incarnation.id,
            version=number,
            event=VersionEvent.INITIAL if number == 1 else VersionEvent.UPDATED,
            configuration=configuration,
            configuration_hash=configuration_hash(configuration, ignored_fields=definition.ignored_fields),
            references=extract_uuid_references(configuration),
        )
        await version.insert()
        versions.append(version)
    return wlan, versions


@pytest.mark.parametrize("chosen", ["current", "older"])
async def test_a_wlan_chosen_with_the_network_it_references_ends_on_the_recreated_network(
    monkeypatch: pytest.MonkeyPatch,
    chosen: str,
) -> None:
    """At its current version the WLAN is only re-pointed; at an older one it is restored, and re-pointed too."""
    organization_id = PydanticObjectId()
    old_network, new_network = str(uuid4()), str(uuid4())
    network = await _deleted_object(
        object_type="networks",
        mist_id=old_network,
        configuration={"id": old_network, "name": "Corp"},
        organization_id=organization_id,
    )
    network_target = await ObjectVersion.find_one(
        ObjectVersion.logical_object_id == network.id, ObjectVersion.version == 1
    )
    assert network_target is not None
    wlan, versions = await _wlan_referencing(organization_id, old_network)
    selected_wlan = versions[1] if chosen == "current" else versions[0]

    operation = await RestorePlanner(store=_MemoryStateStore(), vault=_vault()).create_plan(
        organization_id=organization_id,
        requested_by=PydanticObjectId(),
        version_ids=[network_target.id, selected_wlan.id],
        mode=RestoreMode.NON_DESTRUCTIVE,
        include_dependencies=True,
    )

    assert operation.preflight_errors == []
    reason = RestoreActionReason.REFERENCE_REWRITE if chosen == "current" else RestoreActionReason.RESTORE
    assert [
        (action.logical_object_id, action.action, action.reason, action.depends_on) for action in operation.actions
    ] == [
        (network.id, RestoreActionType.CREATE, RestoreActionReason.RESTORE, []),
        (wlan.id, RestoreActionType.UPDATE, reason, [network.id]),
    ]
    assert operation.actions[1].source_version_id == selected_wlan.id

    identifier = operation.id
    assert identifier is not None
    operation.status = RestoreStatus.QUEUED
    operation.credential_actor = "admin@example.com"
    operation.encrypted_delegated_credential = _vault().encrypt_for_context(
        "api-token", context=f"restore:{identifier}"
    )
    operation.delegated_credential_expires_at = datetime.now(UTC) + timedelta(minutes=10)
    await operation.save()
    client = _MistAfterNetworkDeletion(new_network, wlan.current_mist_id, versions[1].configuration)
    executor, store, notifications, _ = _executor_against(monkeypatch, client, organization_id)

    result = await executor.execute(identifier)

    assert notifications.failed == []
    assert result.status is RestoreStatus.COMPLETED
    assert client.writes == [
        ("create", "networks", {"name": "Corp"}),
        (
            "update",
            wlan.current_mist_id,
            {"ssid": "Corp", "network_id": new_network, "vlan_id": selected_wlan.configuration["vlan_id"]},
        ),
    ]
    state = await store.load(organization_id, identifier)
    assert state is not None
    assert state.verification is not None
    checks = {check.label: check.status for check in state.verification.checks}
    assert checks["Replaced UUID references"] == "ok"
    assert state.verification.verified is True
