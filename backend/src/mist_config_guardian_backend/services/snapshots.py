"""Immutable Mist configuration snapshot collection."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from beanie import Document, PydanticObjectId
from pymongo.errors import DuplicateKeyError

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
from mist_config_guardian_backend.snapshots.canonical_form import changed_top_level_fields
from mist_config_guardian_backend.snapshots.fingerprint import fingerprint, fingerprint_matches, normalize
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

# Attempts at appending an object's next version when concurrent captures of
# the same object keep taking the number first.
_RECORD_ATTEMPTS = 3
# A snapshot still unfinished this long after it started was lost with its
# worker, or with the write that would have finished it. Its manifest would
# otherwise hold the organization's one active slot for good.
STALE_MANIFEST_AFTER = timedelta(hours=6)


class SnapshotOrganizationNotFoundError(ValueError):
    """Raised when snapshot collection targets an unknown organization."""


class SnapshotInProgressError(RuntimeError):
    """Raised when another snapshot of the organization is still running."""


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
            try:
                await open_manifest(manifest)
            except DuplicateKeyError as exc:
                msg = "A snapshot is already in progress"
                raise SnapshotInProgressError(msg) from exc
        elif manifest.organization_id != organization_id:
            msg = "Snapshot manifest does not belong to the requested organization"
            raise ValueError(msg)
        if manifest.id is None:
            msg = "Persisted snapshot manifest is missing an identifier"
            raise RuntimeError(msg)

        counts = SnapshotCounts()
        errors: list[SnapshotError] = []
        context = CollectionContext(organization, manifest.id, counts, errors)

        # Everything from here on finishes the manifest when it fails: one left
        # active would refuse every later snapshot of the organization.
        try:
            manifest.status = SnapshotStatus.RUNNING
            manifest.started_at = utc_now()
            manifest.touch()
            await manifest.save()
            token = await service_token(organization, self._vault)
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
        if status is SnapshotStatus.COMPLETED and manifest.completed_at is not None:
            await _mark_initial_snapshot(organization_id, manifest.completed_at)
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

    @staticmethod
    def source_key(definition: ObjectDefinition, site_id: str | None, mist_object_id: str) -> str:
        """The identity key the collector matches objects by; a restore must record the same one."""
        return f"{site_id or 'org'}:{definition.key}:{mist_object_id}"

    async def capture_configuration(
        self,
        organization_id: PydanticObjectId,
        definition: ObjectDefinition,
        configuration: dict[str, object],
        context: CaptureContext,
    ) -> bool:
        """Append a version when authoritative configuration changed.

        A webhook and a snapshot can capture the same object at once. Whichever
        loses a race on a unique index reads what the other recorded and goes
        on from there, rather than failing.
        """
        mist_object_id = self.object_id(configuration, definition, context.site_id)
        source_key = self.source_key(definition, context.site_id, mist_object_id)
        logical = await _find_or_insert(
            LogicalObject,
            (
                LogicalObject.organization_id == organization_id,
                LogicalObject.scope == definition.scope,
                LogicalObject.object_type == definition.key,
                LogicalObject.source_key == source_key,
            ),
            lambda: LogicalObject(
                organization_id=organization_id,
                scope=definition.scope,
                object_type=definition.key,
                source_key=source_key,
                current_mist_id=mist_object_id,
                site_mist_id=context.site_id,
                name=object_name(configuration, definition),
            ),
        )
        if logical.id is None:
            msg = "Persisted logical object is missing an identifier"
            raise RuntimeError(msg)
        logical_id = logical.id

        incarnation = await _find_or_insert(
            ObjectIncarnation,
            (
                ObjectIncarnation.logical_object_id == logical_id,
                ObjectIncarnation.mist_object_id == mist_object_id,
            ),
            lambda: ObjectIncarnation(
                organization_id=organization_id,
                logical_object_id=logical_id,
                mist_object_id=mist_object_id,
                site_mist_id=context.site_id,
                ordinal=1,
            ),
        )
        if incarnation.id is None:
            msg = "Persisted object incarnation is missing an identifier"
            raise RuntimeError(msg)
        incarnation_id = incarnation.id

        canonical_hash = fingerprint(definition, configuration)

        async def next_version(latest: "ObjectVersion | None") -> "ObjectVersion | None":
            # A tombstone carries the configuration the object was deleted
            # with, so it is never "unchanged": an object seen again after a
            # deletion is live again, even when it came back exactly as it was.
            live = None if latest is None or latest.is_deleted else latest
            if live is not None and fingerprint_matches(definition, live.configuration_hash, configuration):
                # Unchanged, and the only moment the plaintext behind an older
                # digest is in hand: rewrite it in the keyed generation now rather
                # than leave the object waiting on the periodic backfill.
                await _upgrade_stored_hash(live, canonical_hash)
                return None

            previous_configuration = None if live is None else reveal_configuration(live.configuration, self._vault)
            if (
                live is not None
                and previous_configuration is not None
                and normalize(definition, previous_configuration) == normalize(definition, configuration)
            ):
                # The configuration is unchanged under the current registry
                # policy, but its digest was written under an older policy.
                await _upgrade_stored_hash(live, canonical_hash)
                return None

            if latest is None:
                event = context.new_event
            elif live is None:
                event = VersionEvent.CREATED
            else:
                event = VersionEvent.UPDATED
            return ObjectVersion(
                organization_id=organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                snapshot_id=context.snapshot_id,
                version=1 if latest is None else latest.version + 1,
                event=event,
                configuration=protect_configuration(
                    configuration,
                    self._vault,
                    sensitive_fields=definition.sensitive_fields,
                ),
                configuration_hash=canonical_hash,
                changed_fields=(
                    []
                    if previous_configuration is None
                    else changed_top_level_fields(
                        previous_configuration, configuration, ignored_fields=definition.ignored_fields
                    )
                ),
                references=extract_uuid_references(configuration),
                actor=context.actor,
                audit_id=context.audit_id,
            )

        version = await _insert_next_version(organization_id, logical_id, next_version)
        if version is None:
            return False

        logical.current_mist_id = mist_object_id
        logical.name = object_name(configuration, definition)
        logical.current_version = version.version
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
    """Rewrite one version's digest when its generation or field policy is older.

    The write is conditional on the digest still being the one that was read,
    so two workers finding the same unchanged object cannot fight over it, and
    a version rewritten by the backfill in between is left alone.
    """
    previous = version.configuration_hash
    if version.id is None or previous == canonical_hash:
        return
    await ObjectVersion.find_one(
        ObjectVersion.id == version.id,
        ObjectVersion.configuration_hash == previous,
    ).update({"$set": {"configuration_hash": canonical_hash}})
    version.configuration_hash = canonical_hash


async def _find_or_insert[T: Document](
    model: type[T],
    identity: tuple[Mapping[str, Any] | bool, ...],
    new: Callable[[], T],
) -> T:
    """Find a document by its unique identity, or insert ``new()``.

    A concurrent capture of the same new object can insert it first; the one
    that loses the race on the unique index reads the winner's document.
    """
    existing = await model.find_one(*identity)
    if existing is not None:
        return existing
    document = new()
    try:
        await document.insert()
    except DuplicateKeyError:
        existing = await model.find_one(*identity)
        if existing is None:
            raise
        return existing
    return document


async def _insert_next_version(
    organization_id: PydanticObjectId,
    logical_id: PydanticObjectId,
    build: Callable[[ObjectVersion | None], Awaitable[ObjectVersion | None]],
) -> ObjectVersion | None:
    """Append the version ``build`` makes from the newest one, or none when it makes none.

    A concurrent capture of the same object can take the next number first.
    What it recorded is then the newest version, so ``build`` compares against
    that instead, and finds the object unchanged when both read the same thing.
    """
    for attempt in range(1, _RECORD_ATTEMPTS + 1):
        latest = (
            await ObjectVersion.find(
                ObjectVersion.organization_id == organization_id,
                ObjectVersion.logical_object_id == logical_id,
            )
            .sort(-ObjectVersion.version)
            .first_or_none()
        )
        version = await build(latest)
        if version is None:
            return None
        try:
            await version.insert()
        except DuplicateKeyError:
            if attempt == _RECORD_ATTEMPTS:
                raise
            continue
        return version
    msg = "Object history could not be extended"
    raise RuntimeError(msg)


async def open_manifest(manifest: SnapshotManifest) -> None:
    """Insert an active manifest, first releasing one whose snapshot was lost.

    Raises ``DuplicateKeyError`` while another snapshot is still in progress.
    """
    try:
        await manifest.insert()
    except DuplicateKeyError:
        if not await _release_stale_manifest(manifest.organization_id):
            raise
        await manifest.insert()


async def _release_stale_manifest(organization_id: PydanticObjectId) -> bool:
    """Fail the organization's active manifest when its snapshot started too long ago.

    A manifest that never started is judged by when it was queued.
    """
    now = utc_now()
    cutoff = now - STALE_MANIFEST_AFTER
    result = await SnapshotManifest.find_one(
        {
            "organization_id": organization_id,
            "active": True,
            "$or": [
                {"started_at": {"$lt": cutoff}},
                {"started_at": None, "created_at": {"$lt": cutoff}},
            ],
        }
    ).update(
        {
            "$set": {
                "status": SnapshotStatus.FAILED,
                "active": False,
                "completed_at": now,
                "updated_at": now,
                "errors": [
                    SnapshotError(
                        object_type="task",
                        message="Snapshot stopped before it finished",
                        retryable=True,
                    ).model_dump()
                ],
            }
        }
    )
    return result is not None and result.modified_count == 1


async def _mark_initial_snapshot(organization_id: PydanticObjectId, completed_at: datetime) -> None:
    """Record the organization's first complete snapshot, whatever kind it was.

    Only that field is written, and only while it is unset: the organization
    read when a long crawl started is stale by its end, and saving it whole
    would revert a credential rotated in the meantime.
    """
    await Organization.find_one(
        Organization.id == organization_id,
        {"initial_snapshot_completed_at": None},
    ).update({"$set": {"initial_snapshot_completed_at": completed_at, "updated_at": utc_now()}})
