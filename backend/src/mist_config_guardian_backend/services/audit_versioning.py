"""Convert actionable Mist audit receipts into immutable versions."""

from beanie import PydanticObjectId

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
        async with MistConfigurationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            configurations = await client.fetch(
                target.definition,
                org_id=organization.mist_org_id,
                site_id=target.site_id,
            )
        for configuration in configurations:
            object_id = self._snapshots.object_id(
                configuration,
                target.definition,
                target.site_id,
            )
            if target.object_id is not None and object_id != target.object_id:
                continue
            await self._snapshots.capture_configuration(
                receipt.organization_id,
                target.definition,
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
            LogicalObject.object_type == target.definition.key,
            LogicalObject.is_deleted == False,  # noqa: E712
        ]
        if target.object_id:
            filters.append(LogicalObject.current_mist_id == target.object_id)
        elif target.object_name:
            filters.append(LogicalObject.name == target.object_name)
        else:
            return None
        logical = await LogicalObject.find_one(*filters)
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
        latest = (
            await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("-version").first_or_none()
        )
        if latest is None:
            return
        tombstone = ObjectVersion(
            organization_id=logical.organization_id,
            logical_object_id=logical.id,
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
        await tombstone.insert()
        incarnation = await ObjectIncarnation.get(latest.incarnation_id)
        if incarnation is not None and incarnation.ended_at is None:
            incarnation.ended_at = utc_now()
            await incarnation.save()
        logical.current_version = tombstone.version
        logical.is_deleted = True
        logical.touch()
        await logical.save()

    @staticmethod
    def _first_string(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return None
