"""Convert actionable Mist audit receipts into immutable versions."""

import logging
from typing import TYPE_CHECKING

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_config import MistConfigurationClient
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.models.webhook import WebhookReceipt
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.service_credentials import service_token
from mist_config_guardian_backend.services.snapshots import CaptureContext, SnapshotService
from mist_config_guardian_backend.webhooks.audits import AuditTarget, resolve_audit_target

if TYPE_CHECKING:
    from mist_config_guardian_backend.snapshots.registry import ObjectDefinition

logger = logging.getLogger(__name__)

# A deletion re-reads the history and tries again when another writer took the
# version number it was about to use.
_TOMBSTONE_ATTEMPTS = 3


class AuditVersioningService:
    """Fetch authoritative state or append deletion tombstones."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault
        self._snapshots = SnapshotService(vault)

    async def apply(
        self,
        receipt: WebhookReceipt,
        payload: dict[str, object],
        organization: Organization,
    ) -> None:
        """Apply one actionable audit event idempotently."""
        if receipt.topic != "audits":
            return
        target = resolve_audit_target(payload)
        if target is None:
            return
        actor = self._first_string(payload, "admin_name", "admin_id", "user")
        if target.deleted:
            deleted_id = await self._tombstone(
                receipt.organization_id,
                target,
                actor=actor,
                audit_id=receipt.audit_id,
            )
            if target.definition.key == "sites" and deleted_id:
                await self._tombstone_site_children(
                    receipt.organization_id,
                    deleted_id,
                    actor=actor,
                    audit_id=receipt.audit_id,
                )
            return

        token = await service_token(organization, self._vault)
        matches: list[tuple[ObjectDefinition, dict[str, object]]] = []
        async with MistConfigurationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            for definition in target.definitions:
                configurations = await client.fetch(
                    definition,
                    org_id=organization.mist_org_id,
                    site_id=target.site_id,
                )
                matches.extend(
                    (definition, configuration)
                    for configuration in configurations
                    if target.object_id is None
                    or self._snapshots.object_id(configuration, definition, target.site_id) == target.object_id
                )
                if matches and target.object_id is not None:
                    # An identified object is held by one definition only.
                    break
        for definition, configuration in matches:
            await self._snapshots.capture_configuration(
                receipt.organization_id,
                definition,
                configuration,
                CaptureContext(
                    snapshot_id=None,
                    site_id=target.site_id,
                    new_event=VersionEvent.CREATED,
                    actor=actor,
                    audit_id=receipt.audit_id,
                ),
            )

    async def _tombstone(
        self,
        organization_id: PydanticObjectId,
        target: AuditTarget,
        *,
        actor: str | None,
        audit_id: str | None,
    ) -> str | None:
        filters: list[object] = [
            LogicalObject.organization_id == organization_id,
            LogicalObject.scope == target.definition.scope,
            {"object_type": {"$in": [definition.key for definition in target.definitions]}},
            LogicalObject.is_deleted == False,  # noqa: E712
        ]
        if target.object_id:
            filters.append(LogicalObject.current_mist_id == target.object_id)
            logical = await LogicalObject.find_one(*filters)
        elif target.object_name:
            # Mist reports some deleted objects' id as "None", leaving only the
            # name. Names repeat across sites and even within one, so the match
            # is confined to the audit's site and must be unique; anything else
            # is left for the next backup to reconcile.
            filters.append(LogicalObject.name == target.object_name)
            if target.definition.scope == "site":
                filters.append(LogicalObject.site_mist_id == target.site_id)
            named = await LogicalObject.find(*filters).limit(2).to_list()
            if len(named) > 1:
                logger.warning(
                    "Delete audit %s names more than one live %s; none was tombstoned",
                    audit_id,
                    target.definition.key,
                )
                return None
            logical = named[0] if named else None
        else:
            return None
        if logical is None or logical.id is None:
            return None
        await self._tombstone_logical(logical, actor=actor, audit_id=audit_id)
        return logical.current_mist_id

    async def _tombstone_site_children(
        self,
        organization_id: PydanticObjectId,
        site_id: str,
        *,
        actor: str | None,
        audit_id: str | None,
    ) -> None:
        children = await LogicalObject.find(
            LogicalObject.organization_id == organization_id,
            LogicalObject.site_mist_id == site_id,
            LogicalObject.is_deleted == False,  # noqa: E712
        ).to_list()
        for child in children:
            await self._tombstone_logical(child, actor=actor, audit_id=audit_id)

    @staticmethod
    async def _tombstone_logical(
        logical: LogicalObject,
        *,
        actor: str | None,
        audit_id: str | None,
    ) -> None:
        if logical.id is None or logical.is_deleted:
            return
        tombstone = await AuditVersioningService._append_tombstone(logical, actor=actor, audit_id=audit_id)
        if tombstone is None:
            return
        incarnation = await ObjectIncarnation.get(tombstone.incarnation_id)
        if incarnation is not None and incarnation.ended_at is None:
            incarnation.ended_at = utc_now()
            await incarnation.save()
        logical.current_version = tombstone.version
        logical.is_deleted = True
        logical.touch()
        await logical.save()

    @staticmethod
    async def _append_tombstone(
        logical: LogicalObject,
        *,
        actor: str | None,
        audit_id: str | None,
    ) -> ObjectVersion | None:
        """Append a deletion after the newest version, re-reading if another writer took the number.

        A capture of the same object may land between the read and the insert;
        the deletion then follows it. When the newest version already is a
        deletion, another writer recorded this one first and it is returned.
        """
        for attempt in range(1, _TOMBSTONE_ATTEMPTS + 1):
            latest = (
                await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("-version").first_or_none()
            )
            if latest is None or latest.is_deleted:
                return latest
            tombstone = ObjectVersion(
                organization_id=logical.organization_id,
                logical_object_id=latest.logical_object_id,
                incarnation_id=latest.incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.DELETED,
                configuration=latest.configuration,
                configuration_hash=latest.configuration_hash,
                changed_fields=[],
                references=latest.references,
                is_deleted=True,
                actor=actor,
                audit_id=audit_id,
            )
            try:
                await tombstone.insert()
            except DuplicateKeyError:
                if attempt == _TOMBSTONE_ATTEMPTS:
                    raise
                continue
            return tombstone
        msg = "Deletion could not be appended to the object history"
        raise RuntimeError(msg)

    @staticmethod
    def _first_string(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return None
