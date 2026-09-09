"""Immutable Mist configuration snapshot collection."""

from dataclasses import dataclass

from beanie import PydanticObjectId

from mist_config_guardian_backend.integrations.mist_config import (
    MistConfigurationClient,
    MistReadError,
)
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    SnapshotError,
    SnapshotKind,
    SnapshotManifest,
    SnapshotStatus,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.service_credentials import service_token
from mist_config_guardian_backend.snapshots.canonical import (
    changed_top_level_fields,
    configuration_hash,
    configuration_hash_matches,
    is_legacy_hash,
)
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import (
    ORG_OBJECTS,
    SITE_OBJECTS,
    ObjectDefinition,
    object_name,
)
from mist_config_guardian_backend.snapshots.secrets import (
    protect_configuration,
    reveal_configuration,
)


class SnapshotOrganizationNotFoundError(ValueError):
    """Raised when snapshot collection targets an unknown organization."""


@dataclass
class SnapshotCounts:
    """Mutable collection counters."""

    discovered: int = 0
    created: int = 0
    unchanged: int = 0


@dataclass
class CollectionContext:
    """Shared state for one snapshot run."""

    organization: Organization
    snapshot_id: PydanticObjectId
    counts: SnapshotCounts
    errors: list[SnapshotError]


@dataclass(frozen=True)
class CaptureContext:
    """Version metadata for one authoritative object capture."""

    snapshot_id: PydanticObjectId | None
    site_id: str | None
    new_event: VersionEvent = VersionEvent.INITIAL
    actor: str | None = None
    audit_id: str | None = None


class SnapshotService:
    """Collect organization-aware, immutable configuration versions."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def run(
        self,
        organization_id: PydanticObjectId,
        *,
        kind: SnapshotKind,
        manifest_id: PydanticObjectId | None = None,
    ) -> SnapshotManifest:
        """Run one snapshot and retain scoped read failures."""
        organization = await Organization.get(organization_id)
        if organization is None:
            msg = "Organization not found"
            raise SnapshotOrganizationNotFoundError(msg)

        manifest = None if manifest_id is None else await SnapshotManifest.get(manifest_id)
        if manifest is None:
            manifest = SnapshotManifest(
                organization_id=organization_id,
                kind=kind,
            )
            await manifest.insert()
        elif manifest.organization_id != organization_id:
            msg = "Snapshot manifest does not belong to the requested organization"
            raise ValueError(msg)
        manifest.status = SnapshotStatus.RUNNING
        manifest.started_at = utc_now()
        manifest.touch()
        await manifest.save()
        if manifest.id is None:
            msg = "Persisted snapshot manifest is missing an identifier"
            raise RuntimeError(msg)

        counts = SnapshotCounts()
        errors: list[SnapshotError] = []
        context = CollectionContext(organization, manifest.id, counts, errors)
        token = await service_token(organization, self._vault)

        try:
            async with MistConfigurationClient(
                token=token,
                region=organization.cloud_region,
            ) as client:
                sites = await self._collect_scope(
                    client,
                    context,
                    ORG_OBJECTS,
                )
                for site in sites:
                    site_id = site.get("id")
                    if not isinstance(site_id, str) or not site_id:
                        errors.append(
                            SnapshotError(
                                object_type="site",
                                message="Mist returned a site without an id",
                            )
                        )
                        continue
                    await self._collect_scope(
                        client,
                        context,
                        SITE_OBJECTS,
                        site_id=site_id,
                    )
        except Exception:
            await self._finish_manifest(
                manifest,
                counts,
                errors,
                status=SnapshotStatus.FAILED,
            )
            raise

        status = SnapshotStatus.PARTIAL if errors else SnapshotStatus.COMPLETED
        await self._finish_manifest(manifest, counts, errors, status=status)
        if kind is SnapshotKind.INITIAL and status is SnapshotStatus.COMPLETED:
            organization.initial_snapshot_completed_at = manifest.completed_at
            organization.touch()
            await organization.save()
        return manifest

    async def _collect_scope(
        self,
        client: MistConfigurationClient,
        context: CollectionContext,
        definitions: tuple[ObjectDefinition, ...],
        *,
        site_id: str | None = None,
    ) -> list[dict[str, object]]:
        sites: list[dict[str, object]] = []
        organization = context.organization
        if organization.id is None:
            msg = "Persisted organization is missing an identifier"
            raise RuntimeError(msg)

        for definition in definitions:
            try:
                objects = await client.fetch(
                    definition,
                    org_id=organization.mist_org_id,
                    site_id=site_id,
                )
            except MistReadError as exc:
                context.errors.append(
                    SnapshotError(
                        object_type=definition.key,
                        scope_id=site_id,
                        message=str(exc),
                        retryable=True,
                    )
                )
                continue

            for configuration in objects:
                context.counts.discovered += 1
                created = await self.capture_configuration(
                    organization.id,
                    definition,
                    configuration,
                    CaptureContext(snapshot_id=context.snapshot_id, site_id=site_id),
                )
                if created:
                    context.counts.created += 1
                else:
                    context.counts.unchanged += 1
            if definition.scope == "org" and definition.key == "sites":
                sites = objects
        return sites

    async def capture_configuration(
        self,
        organization_id: PydanticObjectId,
        definition: ObjectDefinition,
        configuration: dict[str, object],
        context: CaptureContext,
    ) -> bool:
        """Append a version when authoritative configuration changed."""
        mist_object_id = self.object_id(configuration, definition, context.site_id)
        source_key = f"{context.site_id or 'org'}:{definition.key}:{mist_object_id}"
        logical = await LogicalObject.find_one(
            LogicalObject.organization_id == organization_id,
            LogicalObject.scope == definition.scope,
            LogicalObject.object_type == definition.key,
            LogicalObject.source_key == source_key,
        )
        if logical is None:
            logical = LogicalObject(
                organization_id=organization_id,
                scope=definition.scope,
                object_type=definition.key,
                source_key=source_key,
                current_mist_id=mist_object_id,
                site_mist_id=context.site_id,
                name=object_name(configuration, definition),
            )
            await logical.insert()
        if logical.id is None:
            msg = "Persisted logical object is missing an identifier"
            raise RuntimeError(msg)

        incarnation = await ObjectIncarnation.find_one(
            ObjectIncarnation.logical_object_id == logical.id,
            ObjectIncarnation.mist_object_id == mist_object_id,
        )
        if incarnation is None:
            incarnation = ObjectIncarnation(
                organization_id=organization_id,
                logical_object_id=logical.id,
                mist_object_id=mist_object_id,
                site_mist_id=context.site_id,
                ordinal=1,
            )
            await incarnation.insert()
        if incarnation.id is None:
            msg = "Persisted object incarnation is missing an identifier"
            raise RuntimeError(msg)

        canonical_hash = configuration_hash(
            configuration,
            ignored_fields=definition.ignored_fields,
        )
        latest = (
            await ObjectVersion.find(
                ObjectVersion.organization_id == organization_id,
                ObjectVersion.logical_object_id == logical.id,
            )
            .sort(-ObjectVersion.version)
            .first_or_none()
        )
        if latest is not None and configuration_hash_matches(
            latest.configuration_hash,
            configuration,
            ignored_fields=definition.ignored_fields,
        ):
            # Unchanged, and the only moment the plaintext behind an older
            # digest is in hand: rewrite it in the keyed generation now rather
            # than leave the object waiting on the periodic backfill.
            await _upgrade_stored_hash(latest, canonical_hash)
            return False

        version_number = 1 if latest is None else latest.version + 1
        persisted_configuration = protect_configuration(
            configuration,
            self._vault,
            sensitive_fields=definition.sensitive_fields,
        )
        previous_configuration = None if latest is None else reveal_configuration(latest.configuration, self._vault)
        version = ObjectVersion(
            organization_id=organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            snapshot_id=context.snapshot_id,
            version=version_number,
            event=context.new_event if latest is None else VersionEvent.UPDATED,
            configuration=persisted_configuration,
            configuration_hash=canonical_hash,
            changed_fields=(
                []
                if previous_configuration is None
                else changed_top_level_fields(previous_configuration, configuration)
            ),
            references=extract_uuid_references(configuration),
            actor=context.actor,
            audit_id=context.audit_id,
        )
        await version.insert()

        logical.current_mist_id = mist_object_id
        logical.name = object_name(configuration, definition)
        logical.current_version = version_number
        logical.is_deleted = False
        logical.touch()
        await logical.save()
        return True

    @staticmethod
    def object_id(
        configuration: dict[str, object],
        definition: ObjectDefinition,
        site_id: str | None,
    ) -> str:
        object_id = configuration.get("id")
        if isinstance(object_id, str) and object_id:
            return object_id
        return f"{site_id or 'org'}:{definition.key}"

    @staticmethod
    async def _finish_manifest(
        manifest: SnapshotManifest,
        counts: SnapshotCounts,
        errors: list[SnapshotError],
        *,
        status: SnapshotStatus,
    ) -> None:
        manifest.status = status
        manifest.active = False
        manifest.completed_at = utc_now()
        manifest.discovered_objects = counts.discovered
        manifest.created_versions = counts.created
        manifest.unchanged_objects = counts.unchanged
        manifest.errors = errors
        manifest.touch()
        await manifest.save()


async def _upgrade_stored_hash(version: ObjectVersion, canonical_hash: str) -> None:
    """Rewrite one version's digest in the keyed generation, if it is older.

    The write is conditional on the digest still being the one that was read,
    so two workers finding the same unchanged object cannot fight over it, and
    a version rewritten by the backfill in between is left alone.
    """
    previous = version.configuration_hash
    if version.id is None or not is_legacy_hash(previous):
        return
    await ObjectVersion.find_one(
        ObjectVersion.id == version.id,
        ObjectVersion.configuration_hash == previous,
    ).update({"$set": {"configuration_hash": canonical_hash}})
    version.configuration_hash = canonical_hash
