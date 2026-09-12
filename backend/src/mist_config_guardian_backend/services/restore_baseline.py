"""Capture an administrator-view backup before constructing a new reviewable plan."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.integrations.mist_mutation import MistMutationClient
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectVersion,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import organization_policy
from mist_config_guardian_backend.services.restore_planner import (
    RestorePlanner,
    RestorePlanningError,
    RestoreStateStore,
    latest_version,
)
from mist_config_guardian_backend.snapshots.canonical import changed_top_level_fields, configuration_hash
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    find_unavailable_secrets,
    protect_configuration,
    reveal_configuration,
)


class RestoreBaselineService:
    """Pin action baselines to the exact immutable versions just captured."""

    def __init__(self, vault: CredentialVault, store: RestoreStateStore) -> None:
        self._vault = vault
        self._store = store

    async def prepare(
        self,
        organization: Organization,
        source: RestoreOperation,
        requested_by: PydanticObjectId,
        credential: str,
        actor: str | None,
    ) -> RestoreOperation:
        if not source.requested_version_ids:
            msg = "Select the target versions again before preparing a fresh backup"
            raise RestorePlanningError(msg)
        manifest = SnapshotManifest(
            organization_id=source.organization_id,
            kind=SnapshotKind.MANUAL,
            status=SnapshotStatus.RUNNING,
            started_at=utc_now(),
        )
        await manifest.insert()
        try:
            # The caller owns the delegated session; closing this HTTP client
            # must not log it out before the reviewer has approved the new plan.
            client = MistMutationClient(token=credential, region=organization.cloud_region)
            try:

                async def read_baselines(
                    objects: dict[PydanticObjectId, LogicalObject],
                ) -> dict[PydanticObjectId, ObjectVersion]:
                    return await self._capture(client, organization, objects, manifest, actor)

                plan = await RestorePlanner(
                    self._store,
                    organization_policy(organization),
                    self._vault,
                    baseline_reader=read_baselines,
                ).create_plan(
                    organization_id=source.organization_id,
                    requested_by=requested_by,
                    version_ids=source.requested_version_ids,
                    mode=source.mode,
                    include_dependencies=source.include_dependencies,
                )
            finally:
                await client.close_transport()
            plan.baseline_snapshot_id = manifest.id
            plan.warnings.append("A fresh pre-restore backup was captured. Review this new plan before executing it.")
            await plan.save()
            manifest.status = SnapshotStatus.COMPLETED
        except Exception:
            manifest.status = SnapshotStatus.FAILED
            raise
        finally:
            manifest.active = False
            manifest.completed_at = utc_now()
            manifest.touch()
            await manifest.save()
        return plan

    async def _capture(
        self,
        client: MistMutationClient,
        organization: Organization,
        objects: dict[PydanticObjectId, LogicalObject],
        manifest: SnapshotManifest,
        actor: str | None,
    ) -> dict[PydanticObjectId, ObjectVersion]:
        baselines = {}
        for logical_id, logical in objects.items():
            definition = get_definition(logical.scope, logical.object_type)
            previous = await latest_version(logical_id)
            if definition is None or previous is None:
                msg = "A restore target has no supported baseline"
                raise RestorePlanningError(msg)
            current = await client.get_current(
                definition,
                logical.current_mist_id,
                org_id=organization.mist_org_id,
                site_id=logical.site_mist_id,
            )
            if (current is None) != logical.is_deleted:
                msg = "An object was created or deleted since backup; refresh organization history and rebuild the plan"
                raise RestorePlanningError(msg)
            if current is None:
                baselines[logical_id] = previous
                manifest.unchanged_objects += 1
                continue
            if find_unavailable_secrets(current, definition.sensitive_fields):
                msg = "The administrator response contains unavailable secrets; a recoverable backup cannot be made"
                raise RestorePlanningError(msg)
            version = ObjectVersion(
                organization_id=logical.organization_id,
                logical_object_id=logical_id,
                incarnation_id=previous.incarnation_id,
                snapshot_id=manifest.id,
                version=previous.version + 1,
                event=VersionEvent.UPDATED,
                configuration=protect_configuration(current, self._vault, sensitive_fields=definition.sensitive_fields),
                configuration_hash=configuration_hash(current, ignored_fields=definition.ignored_fields),
                changed_fields=changed_top_level_fields(
                    reveal_configuration(previous.configuration, self._vault), current
                ),
                references=extract_uuid_references(current),
                actor=actor,
            )
            await version.insert()
            await LogicalObject.find_one(LogicalObject.id == logical_id).update(
                {"$max": {"current_version": version.version}, "$set": {"updated_at": utc_now()}},
            )
            baselines[logical_id] = version
            manifest.created_versions += 1
        manifest.discovered_objects = len(objects)
        return baselines
