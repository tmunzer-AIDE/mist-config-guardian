"""Asynchronous processing for durable webhook receipts."""

import json
from datetime import UTC, datetime

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.monitoring import MonitoringSession
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.webhook import (
    AuditChangeGroup,
    WebhookProcessingStatus,
    WebhookReceipt,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.audit_versioning import AuditVersioningService
from mist_config_guardian_backend.services.change_groups import ChangeGroupProjector
from mist_config_guardian_backend.services.monitoring import MonitoringEventService
from mist_config_guardian_backend.services.notifications import NotificationService

# Mist stamps audit and device events with an epoch timestamp. Values far in the
# past are milliseconds, not seconds; the boundary is well before Mist existed.
_EPOCH_MILLISECOND_BOUNDARY = 100_000_000_000


class WebhookReceiptNotFoundError(ValueError):
    """Raised when a queued webhook receipt no longer exists."""


class WebhookProcessingService:
    """Decrypt and correlate authenticated webhook receipts."""

    def __init__(
        self,
        vault: CredentialVault,
        projector: ChangeGroupProjector | None = None,
    ) -> None:
        self._vault = vault
        self._projector = (
            projector if projector is not None else ChangeGroupProjector(notifications=NotificationService())
        )

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
        # The projection is rebuilt from scratch afterwards, so it does not
        # matter whether the audit event or the device events arrived first, or
        # how many times either was delivered.
        await self.project(receipt, payload)

        receipt.status = WebhookProcessingStatus.PROCESSED
        receipt.processed_at = utc_now()
        receipt.touch()
        await receipt.save()

    async def project(self, receipt: WebhookReceipt, payload: dict[str, object]) -> None:
        """Recompute every change-group projection this receipt can affect."""
        for audit_id in sorted(await self._affected_audit_ids(receipt, payload)):
            await self._projector.rebuild(receipt.organization_id, audit_id)

    @staticmethod
    async def _affected_audit_ids(
        receipt: WebhookReceipt,
        payload: dict[str, object],
    ) -> set[str]:
        if receipt.audit_id:
            return {receipt.audit_id}
        # A device event that carries no audit identifier still belongs to the
        # administrator action its session was opened for.
        device_mac = WebhookProcessingService._first_string(payload, "mac", "device_mac", "ap_mac")
        if receipt.topic != "device-events" or not device_mac:
            return set()
        session = await MonitoringSession.find_one(
            MonitoringSession.organization_id == receipt.organization_id,
            MonitoringSession.device_mac == device_mac.replace(":", "").replace("-", "").lower(),
        )
        return set(session.audit_ids) if session is not None else set()

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
                occurred_at=WebhookProcessingService._event_time(payload) or receipt.created_at,
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
        # A later delivery of the same audit may be the one that carries the
        # actor or the message, so fill blanks without overwriting known values.
        group.actor = group.actor or WebhookProcessingService._first_string(
            payload,
            "admin_name",
            "admin_id",
            "user",
        )
        group.method = group.method or WebhookProcessingService._first_string(payload, "method", "src")
        group.message = group.message or WebhookProcessingService._first_string(payload, "message")
        group.occurred_at = group.occurred_at or WebhookProcessingService._event_time(payload)
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
    def _event_time(payload: dict[str, object]) -> datetime | None:
        for key in ("timestamp", "when", "occurred_at"):
            value = payload.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                seconds = value / 1000 if value > _EPOCH_MILLISECOND_BOUNDARY else value
                return datetime.fromtimestamp(seconds, tz=UTC)
        return None

    @staticmethod
    def _first_string(payload: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value:
                return value
        return None
