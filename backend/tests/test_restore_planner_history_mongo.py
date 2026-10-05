"""Database-backed checks of which instant a restore plan judges related objects at.

The collector stamps every version as it builds it, one object after another,
so a snapshot spreads over an interval rather than an instant. These tests
record history the way the collector and the audit pipeline do and plan
against it, so the timestamps under test are the ones a deployment stores.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import asyncio
import os
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.approval import ApprovalPolicy, ApprovalRule
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import MistCloudRegion, Organization, OrganizationStatus
from mist_config_guardian_backend.models.restore import RestoreActionType, RestoreMode, RestoreOperation
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import evaluate_approval_policy
from mist_config_guardian_backend.services.audit_versioning import AuditVersioningService
from mist_config_guardian_backend.services.restore_compensation import capture_safety_snapshot
from mist_config_guardian_backend.services.restore_planner import RestorePlanner, latest_version
from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService
from mist_config_guardian_backend.snapshots.registry import get_definition

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "restore_planner_history"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]

SITE = "11111111-1111-4111-8111-111111111111"
NETWORK_TEMPLATE = "22222222-2222-4222-8222-222222222222"
WLAN = "33333333-3333-4333-8333-333333333333"
NETWORK = "44444444-4444-4444-8444-444444444444"
REVIVED_WLAN = "55555555-5555-4555-8555-555555555555"
HAND_MADE_WLAN = "88888888-8888-4888-8888-888888888888"
ORG = "66666666-6666-4666-8666-666666666666"
TEMPLATE = "77777777-7777-4777-8777-777777777777"

# Long enough that consecutive captures never share MongoDB's millisecond.
_TICK = 0.005


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(
        database=client[DATABASE],
        document_models=[LogicalObject, ObjectIncarnation, ObjectVersion, RestoreOperation, SnapshotManifest],
    )
    yield
    await client.drop_database(DATABASE)
    await client.close()


def _vault() -> CredentialVault:
    return CredentialVault(Settings(environment="test", credential_encryption_key="test-key"))


class _History:
    """One organization's history, recorded through the collector's own capture."""

    def __init__(self) -> None:
        self.organization_id = PydanticObjectId()
        self._snapshots = SnapshotService(_vault())

    async def capture(
        self,
        scope: str,
        object_type: str,
        configuration: dict[str, object],
        *,
        snapshot: SnapshotManifest | None = None,
        site_id: str | None = None,
    ) -> None:
        """Record one read, a moment after the previous one, as the collector or a webhook would."""
        await asyncio.sleep(_TICK)
        definition = get_definition(scope, object_type)
        assert definition is not None
        await self._snapshots.capture_configuration(
            self.organization_id,
            definition,
            configuration,
            CaptureContext(snapshot_id=None if snapshot is None else snapshot.id, site_id=site_id),
        )

    async def start_snapshot(self, kind: SnapshotKind = SnapshotKind.INITIAL) -> SnapshotManifest:
        manifest = SnapshotManifest(
            organization_id=self.organization_id,
            kind=kind,
            status=SnapshotStatus.RUNNING,
            started_at=utc_now(),
        )
        await manifest.insert()
        return manifest

    @staticmethod
    async def finish(manifest: SnapshotManifest) -> None:
        await asyncio.sleep(_TICK)
        manifest.status = SnapshotStatus.COMPLETED
        manifest.active = False
        manifest.completed_at = utc_now()
        await manifest.save()

    async def logical(self, mist_id: str) -> LogicalObject:
        logical = await LogicalObject.find_one(
            LogicalObject.organization_id == self.organization_id,
            LogicalObject.current_mist_id == mist_id,
        )
        assert logical is not None
        return logical

    async def version(self, mist_id: str, number: int) -> ObjectVersion:
        logical = await self.logical(mist_id)
        version = await ObjectVersion.find_one(
            ObjectVersion.logical_object_id == logical.id,
            ObjectVersion.version == number,
        )
        assert version is not None
        return version

    async def delete(self, mist_id: str) -> None:
        """Record a deletion the way an audit webhook does."""
        await asyncio.sleep(_TICK)
        await AuditVersioningService._tombstone_logical(  # noqa: SLF001 - the audit pipeline's own tombstone
            await self.logical(mist_id), actor=None, audit_id=None
        )

    async def restored(self, logical: LogicalObject, configuration: dict[str, object], new_id: str) -> None:
        """Record an object brought back by a restore on its logical object, under a new id."""
        await asyncio.sleep(_TICK)
        latest = await latest_version(logical.id)
        assert latest is not None
        incarnation = ObjectIncarnation(
            organization_id=self.organization_id,
            logical_object_id=logical.id,
            mist_object_id=new_id,
            site_mist_id=logical.site_mist_id,
            ordinal=2,
        )
        await incarnation.insert()
        await ObjectVersion(
            organization_id=self.organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            version=latest.version + 1,
            event=VersionEvent.RESTORED,
            configuration=configuration,
            configuration_hash=f"restored-{new_id}",
        ).insert()
        await LogicalObject.find_one(LogicalObject.id == logical.id).update(
            {
                "$set": {
                    "is_deleted": False,
                    "current_mist_id": new_id,
                    "source_key": f"{logical.site_mist_id or 'org'}:{logical.object_type}:{new_id}",
                }
            }
        )

    async def plan(self, versions: list[ObjectVersion], mode: RestoreMode) -> RestoreOperation:
        return await RestorePlanner(store=AsyncMock(), vault=_vault()).create_plan(
            organization_id=self.organization_id,
            requested_by=PydanticObjectId(),
            version_ids=[version.id for version in versions],
            mode=mode,
            include_dependencies=True,
        )


def _summary(plan: RestoreOperation) -> list[tuple[str, RestoreActionType]]:
    return sorted((action.object_type, action.action) for action in plan.actions)


# ------------------------------------------------------------ one snapshot, one instant


@pytest.mark.parametrize("finished", [True, False])
async def test_an_exact_site_restore_keeps_what_the_same_snapshot_recorded_after_the_site(
    finished: bool,  # noqa: FBT001 - a pytest parameter
) -> None:
    """The template the site names and the WLAN in it were read moments after the site, in the same snapshot."""
    history = _History()
    initial = await history.start_snapshot()
    # The collector's registry order: sites, then templates, then site-scoped objects.
    site = {"id": SITE, "name": "HQ", "networktemplate_id": NETWORK_TEMPLATE, "timezone": "UTC"}
    await history.capture("org", "sites", site, snapshot=initial)
    await history.capture("org", "networktemplates", {"id": NETWORK_TEMPLATE, "name": "Campus"}, snapshot=initial)
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp"}, snapshot=initial, site_id=SITE)
    if finished:
        await history.finish(initial)
    # Someone edits the site later; the requester rolls that edit back.
    await history.capture("org", "sites", {**site, "timezone": "Europe/Paris"})

    plan = await history.plan([await history.version(SITE, 1)], RestoreMode.EXACT)

    assert _summary(plan) == [("sites", RestoreActionType.UPDATE)]


async def test_an_exact_site_restore_keeps_an_object_created_while_its_snapshot_ran() -> None:
    """Created after the site was read, then read unchanged by the same snapshot, so it holds no snapshot version."""
    history = _History()
    initial = await history.start_snapshot()
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"}, snapshot=initial)
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp"}, site_id=SITE)
    await history.finish(initial)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"})

    plan = await history.plan([await history.version(SITE, 1)], RestoreMode.EXACT)

    assert _summary(plan) == [("sites", RestoreActionType.UPDATE)]


async def test_an_exact_organization_restore_keeps_everything_its_snapshot_recorded() -> None:
    history = _History()
    initial = await history.start_snapshot()
    await history.capture("org", "data", {"id": ORG, "name": "Lab"}, snapshot=initial)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"}, snapshot=initial)
    await history.capture("org", "networks", {"id": NETWORK, "name": "Corp"}, snapshot=initial)
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp"}, snapshot=initial, site_id=SITE)
    await history.finish(initial)
    await history.capture("org", "data", {"id": ORG, "name": "Lab renamed"})

    plan = await history.plan([await history.version(ORG, 1)], RestoreMode.EXACT)

    assert _summary(plan) == [("data", RestoreActionType.UPDATE)]


async def test_a_non_destructive_restore_keeps_changes_its_reconciliation_recorded_after_the_site() -> None:
    history = _History()
    initial = await history.start_snapshot()
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"}, snapshot=initial)
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp", "vlan_id": 10}, snapshot=initial, site_id=SITE)
    await history.finish(initial)
    reconciliation = await history.start_snapshot(SnapshotKind.RECONCILIATION)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"}, snapshot=reconciliation)
    await history.capture(
        "site", "wlans", {"id": WLAN, "ssid": "Corp", "vlan_id": 20}, snapshot=reconciliation, site_id=SITE
    )
    await history.finish(reconciliation)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "Europe/Paris"})

    plan = await history.plan([await history.version(SITE, 2)], RestoreMode.NON_DESTRUCTIVE)

    # The WLAN's state in that reconciliation is its current one, so it is not rolled back.
    assert _summary(plan) == [("sites", RestoreActionType.UPDATE)]


async def test_each_selected_version_judges_its_own_dependencies_at_its_own_instant() -> None:
    """A template chosen at a later version is not dragged back to the instant of an older selection."""
    history = _History()
    await history.capture("org", "networks", {"id": NETWORK, "name": "Corp", "vlan_id": 10})
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"})
    await history.capture("org", "networks", {"id": NETWORK, "name": "Corp", "vlan_id": 20})
    await history.capture("org", "templates", {"id": TEMPLATE, "name": "Branch", "network_id": NETWORK})
    await history.capture("org", "templates", {"id": TEMPLATE, "name": "Branch v2", "network_id": NETWORK})
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"})

    plan = await history.plan(
        [await history.version(SITE, 1), await history.version(TEMPLATE, 1)],
        RestoreMode.NON_DESTRUCTIVE,
    )

    # The network the template referenced at its own version is the network as it is now.
    assert _summary(plan) == [("sites", RestoreActionType.UPDATE), ("templates", RestoreActionType.UPDATE)]


async def test_an_exact_restore_never_deletes_an_object_a_restored_version_references() -> None:
    """Audit events arrive out of order: the site is recorded naming a template recorded after it."""
    history = _History()
    site = {"id": SITE, "name": "HQ", "networktemplate_id": NETWORK_TEMPLATE}
    await history.capture("org", "sites", site)
    await history.capture("org", "networktemplates", {"id": NETWORK_TEMPLATE, "name": "Campus", "network_id": NETWORK})
    # What the template references is kept too, however it was reached.
    await history.capture("org", "networks", {"id": NETWORK, "name": "Corp"})
    await history.capture("org", "sites", {**site, "timezone": "UTC"})

    plan = await history.plan([await history.version(SITE, 1)], RestoreMode.EXACT)

    assert _summary(plan) == [("sites", RestoreActionType.UPDATE)]


async def test_an_exact_restore_still_deletes_what_was_created_after_the_snapshot() -> None:
    history = _History()
    initial = await history.start_snapshot()
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"}, snapshot=initial)
    await history.finish(initial)
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp"}, site_id=SITE)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"})

    plan = await history.plan([await history.version(SITE, 1)], RestoreMode.EXACT)

    assert _summary(plan) == [("sites", RestoreActionType.UPDATE), ("wlans", RestoreActionType.DELETE)]


# ----------------------------------------- deleted at the target, brought back since


@pytest.mark.parametrize("mode", [RestoreMode.NON_DESTRUCTIVE, RestoreMode.EXACT])
async def test_an_object_deleted_at_the_target_and_restored_since_is_deleted_only_by_an_exact_plan(
    mode: RestoreMode,
) -> None:
    history = _History()
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"})
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp"}, site_id=SITE)
    await history.delete(WLAN)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"})
    # A restore brings the WLAN back afterwards, on the same logical object.
    await history.restored(await history.logical(WLAN), {"id": REVIVED_WLAN, "ssid": "Corp"}, REVIVED_WLAN)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "Europe/Paris"})

    plan = await history.plan([await history.version(SITE, 2)], mode)

    if mode is RestoreMode.NON_DESTRUCTIVE:
        # Kept, like any object created after the selected timestamp (spec §9.1).
        assert _summary(plan) == [("sites", RestoreActionType.UPDATE)]
    else:
        assert _summary(plan) == [("sites", RestoreActionType.UPDATE), ("wlans", RestoreActionType.DELETE)]
        rules = evaluate_approval_policy(ApprovalPolicy(enabled=True), plan.actions, plan.mode)
        assert ApprovalRule.EXACT_MODE_DELETES in {rule.rule for rule in rules}


# --------------------------------------------- a replacement holding the name back


class _Mist:
    """Mist as it is now, answering the preflight's reads."""

    def __init__(self, *objects: dict[str, object]) -> None:
        self.objects = {str(item["id"]): dict(item) for item in objects}

    async def get_current(self, definition, object_id, *, org_id, site_id):  # noqa: ARG002
        found = self.objects.get(object_id)
        return None if found is None else dict(found)

    async def list_objects(self, definition, *, org_id, site_id):  # noqa: ARG002
        return [dict(item) for item in self.objects.values() if definition.key == "wlans" and "ssid" in item]


async def test_an_exact_plan_deletes_a_hand_made_replacement_before_recreating_the_original() -> None:
    history = _History()
    await history.capture("org", "sites", {"id": SITE, "name": "HQ"})
    await history.capture("site", "wlans", {"id": WLAN, "ssid": "Corp", "vlan_id": 10}, site_id=SITE)
    await history.capture("org", "sites", {"id": SITE, "name": "HQ", "timezone": "UTC"})
    # Someone deletes the WLAN and recreates it by hand under the same SSID.
    await history.delete(WLAN)
    replacement = {"id": HAND_MADE_WLAN, "ssid": "Corp", "vlan_id": 99}
    await history.capture("site", "wlans", replacement, site_id=SITE)
    site = {"id": SITE, "name": "HQ", "timezone": "Europe/Paris"}
    await history.capture("org", "sites", site)

    plan = await history.plan([await history.version(SITE, 2)], RestoreMode.EXACT)

    assert [(action.current_mist_id, action.action) for action in plan.actions if action.object_type == "wlans"] == [
        (HAND_MADE_WLAN, RestoreActionType.DELETE),
        (WLAN, RestoreActionType.CREATE),
    ]
    organization = Organization.model_construct(
        id=history.organization_id,
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
    )
    # The name the original needs is held only by the object the plan deletes first.
    entries = await capture_safety_snapshot(_Mist(site, replacement), organization, plan, _vault())
    assert len(entries) == len(plan.actions)
