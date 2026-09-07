"""Asynchronous processing for durable webhook receipts."""

import json

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.webhook import (
    AuditChangeGroup,
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.audit_versioning import AuditVersioningService
from mist_config_guardian_backend.services.monitoring import MonitoringEventService


class WebhookReceiptNotFoundError(ValueError):
    """Raised when a queued webhook receipt no longer exists."""


class WebhookProcessingService:
    """Decrypt and correlate authenticated webhook receipts."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def process(self, receipt_id: PydanticObjectId) -> None:
        """Process one receipt idempotently."""
        receipt = await WebhookReceipt.get(receipt_id)
        if receipt is None:
            msg = "Webhook receipt not found"
            raise WebhookReceiptNotFoundError(msg)
        if receipt.status is WebhookProcessingStatus.PROCESSED:
            return

        organization = await Organization.get(receipt.organization_id)
        if organization is None:
            msg = "Webhook organization not found"
            raise WebhookReceiptNotFoundError(msg)

        receipt.status = WebhookProcessingStatus.PROCESSING
        receipt.processing_attempts += 1
        receipt.processing_error = None
        receipt.touch()
        await receipt.save()

        serialized = self._vault.decrypt_for_context(
            receipt.encrypted_payload,
            context=f"webhook-payload:{organization.mist_org_id}",
        )
        payload = json.loads(serialized)
        if not isinstance(payload, dict):
            msg = "Stored webhook payload must be an object"
            raise TypeError(msg)

        if receipt.audit_id:
            await self._add_to_change_group(receipt, payload)
        await AuditVersioningService(self._vault).apply(receipt, payload, organization)
        await MonitoringEventService(self._vault).handle(receipt, payload, organization)

        receipt.status = WebhookProcessingStatus.PROCESSED
        receipt.processed_at = utc_now()
        receipt.touch()
        await receipt.save()

    @staticmethod
    async def _add_to_change_group(
        receipt: WebhookReceipt,
        payload: dict[str, object],
    ) -> None:
        if receipt.id is None or receipt.audit_id is None:
            return
        group = await AuditChangeGroup.find_one(
            AuditChangeGroup.organization_id == receipt.organization_id,
            AuditChangeGroup.audit_id == receipt.audit_id,
        )
        if group is None:
            group = AuditChangeGroup(
                organization_id=receipt.organization_id,
                audit_id=receipt.audit_id,
                actor=WebhookProcessingService._first_string(
                    payload,
                    "admin_name",
                    "admin_id",
                    "user",
                ),
                method=WebhookProcessingService._first_string(
                    payload,
                    "method",
                    "src",
                ),
                message=WebhookProcessingService._first_string(payload, "message"),
            )
            try:
                await group.insert()
            except DuplicateKeyError:
                group = await AuditChangeGroup.find_one(
                    AuditChangeGroup.organization_id == receipt.organization_id,
                    AuditChangeGroup.audit_id == receipt.audit_id,
                )
                if group is None:
                    raise

        if receipt.id not in group.receipt_ids:
            group.receipt_ids.append(receipt.id)
        site_id = WebhookProcessingService._first_string(payload, "site_id")
        if site_id and site_id not in group.affected_site_ids:
            group.affected_site_ids.append(site_id)
        object_id = WebhookProcessingService._first_string(
            payload,
            "object_id",
            "device_id",
            "id",
        )
        if object_id and object_id not in group.affected_object_ids:
            group.affected_object_ids.append(object_id)
        group.touch()
        await group.save()

    @staticmethod
    def _first_string(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return None
