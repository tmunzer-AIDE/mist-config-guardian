"""Asynchronous processing for durable webhook receipts."""

import json
from datetime import UTC, datetime, timedelta

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import get_settings
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
from mist_config_guardian_backend.services.guardian import GuardianService
from mist_config_guardian_backend.services.monitoring import MonitoringEventService
from mist_config_guardian_backend.services.network_impact_policy import exclusion_reason
from mist_config_guardian_backend.services.notifications import NotificationService

# Mist stamps audit and device events with an epoch timestamp. Values far in the
# past are milliseconds, not seconds; the boundary is well before Mist existed.
_EPOCH_MILLISECOND_BOUNDARY = 100_000_000_000

# A receipt whose processing failed is tried again after a delay that doubles
# with each attempt, a bounded number of times; the last error stays on it.
MAX_PROCESSING_ATTEMPTS = 5
RETRY_BASE_DELAY = timedelta(minutes=5)
# Processing takes seconds. A receipt still queued or in progress this long
# after it was last touched has lost its queue message or its worker.
STALE_AFTER = timedelta(minutes=30)
# Processing records the object as Mist holds it now. Past this age that state
# would be attributed to an action it may not reflect, so the receipt is left
# to the next snapshot instead.
RETRY_WINDOW = timedelta(days=1)
RETRY_BATCH_SIZE = 100
_PROCESSING_ERROR_LIMIT = 500


class WebhookReceiptNotFoundError(ValueError):
    """Raised when a queued webhook receipt no longer exists."""


def _union(field: str, values: list[object]) -> dict[str, object]:
    """Add values to an array field without duplicating what is already there."""
    return {"$setUnion": [{"$ifNull": [field, []]}, values]}


def _fill(field: str, value: object) -> dict[str, object]:
    """Set a field only while it is still empty."""
    return {"$ifNull": [field, value]}


def retry_delay(attempts: int) -> timedelta:
    """How long a receipt waits after its ``attempts``-th failed attempt."""
    return RETRY_BASE_DELAY * 2 ** (attempts - 1)


async def claim_retryable_receipts(
    *,
    now: datetime | None = None,
    limit: int = RETRY_BATCH_SIZE,
) -> list[PydanticObjectId]:
    """Mark the receipts due another attempt as queued and return them.

    A receipt is due when the queue refused it, when its last attempt failed
    and its delay has passed, or when its queue message or worker was lost.
    Each is claimed only if it is unchanged since it was read, so overlapping
    sweeps cannot queue it twice, and claiming touches it, so the next sweep
    leaves it to the worker.
    """
    now = now or utc_now()
    collection = WebhookReceipt.get_pymongo_collection()
    candidates = (
        await collection.find(
            {
                "created_at": {"$gte": now - RETRY_WINDOW},
                "processing_attempts": {"$lt": MAX_PROCESSING_ATTEMPTS},
                "$or": [
                    {"status": WebhookProcessingStatus.RECEIVED.value},
                    *(
                        {
                            "status": WebhookProcessingStatus.FAILED.value,
                            "processing_attempts": attempts,
                            "updated_at": {"$lte": now - retry_delay(attempts)},
                        }
                        for attempts in range(1, MAX_PROCESSING_ATTEMPTS)
                    ),
                    {
                        "status": {
                            "$in": [WebhookProcessingStatus.QUEUED.value, WebhookProcessingStatus.PROCESSING.value]
                        },
                        "updated_at": {"$lte": now - STALE_AFTER},
                    },
                ],
            },
            {"status": 1, "updated_at": 1},
        )
        .sort("updated_at", 1)
        .limit(limit)
        .to_list(length=limit)
    )
    claimed: list[PydanticObjectId] = []
    for candidate in candidates:
        result = await collection.update_one(
            {"_id": candidate["_id"], "status": candidate["status"], "updated_at": candidate["updated_at"]},
            {"$set": {"status": WebhookProcessingStatus.QUEUED.value, "updated_at": now}},
        )
        if result.modified_count:
            claimed.append(PydanticObjectId(candidate["_id"]))
    return claimed


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

        try:
            await self._process(receipt, organization)
        except Exception as exc:
            # Recorded rather than left in progress, so the retry sweep finds it
            # and the reason is kept; processing is idempotent, so a retry
            # repeats nothing an earlier attempt already recorded.
            receipt.status = WebhookProcessingStatus.FAILED
            receipt.processing_error = f"{type(exc).__name__}: {exc}"[:_PROCESSING_ERROR_LIMIT]
            receipt.touch()
            await receipt.save()
            raise

        receipt.status = WebhookProcessingStatus.PROCESSED
        receipt.processed_at = utc_now()
        receipt.touch()
        await receipt.save()

    async def _process(self, receipt: WebhookReceipt, organization: Organization) -> None:
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
        linked = (
            await AuditChangeGroup.find_one({"organization_id": receipt.organization_id, "audit_id": receipt.audit_id})
            if receipt.topic == "device-events" and receipt.audit_id
            else None
        )
        session = (
            None
            if linked and exclusion_reason(linked.changed_objects, linked.message)
            else await MonitoringEventService(self._vault).handle(receipt, payload, organization)
        )
        # The projection is rebuilt from scratch afterwards, so it does not
        # matter whether the audit event or the device events arrived first, or
        # how many times either was delivered.
        projected = await self.project(receipt, payload, session=session)

        if receipt.topic == "audits" and receipt.audit_id:
            settings = get_settings()
            event_time = self._event_time(payload)
            if (
                settings.guardian_enabled
                and (projected is None or projected.changed_objects)
                and not (
                    exclusion_reason(projected.changed_objects, projected.message)
                    if projected
                    else exclusion_reason([], self._first_string(payload, "message"))
                )
            ):
                await GuardianService(self._vault).ensure(
                    organization,
                    receipt.audit_id,
                    changed_at=event_time or receipt.created_at,
                    anchor_known=event_time is not None,
                )

    async def project(
        self,
        receipt: WebhookReceipt,
        payload: dict[str, object],
        *,
        session: MonitoringSession | None = None,
    ) -> AuditChangeGroup | None:
        """Recompute every change-group projection this receipt can affect.

        ``session`` is the monitoring session the event handler changed, when
        the caller ran it. A device event without an audit identifier belongs
        to whichever administrator action that session was opened for.
        """
        projected = None
        for audit_id in sorted(await self._affected_audit_ids(receipt, payload, session)):
            group = await self._projector.rebuild(receipt.organization_id, audit_id)
            if audit_id == receipt.audit_id:
                projected = group
        return projected

    @staticmethod
    async def _affected_audit_ids(
        receipt: WebhookReceipt,
        payload: dict[str, object],
        session: MonitoringSession | None,
    ) -> set[str]:
        if receipt.audit_id:
            return {receipt.audit_id}
        if session is not None:
            return set(session.audit_ids)
        device_mac = WebhookProcessingService._first_string(payload, "mac", "device_mac", "ap_mac")
        if receipt.topic != "device-events" or not device_mac:
            return set()
        # Without the handler's answer, choose the way it would: a device has one
        # active session at most, and the newest is otherwise the one the event
        # belongs to. An unordered lookup could return a session from months ago
        # and attribute this evidence to an unrelated change.
        session = (
            await MonitoringSession.find(
                MonitoringSession.organization_id == receipt.organization_id,
                MonitoringSession.device_mac == device_mac.replace(":", "").replace("-", "").lower(),
            )
            .sort("-active", "-created_at")
            .first_or_none()
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

        site_id = WebhookProcessingService._first_string(payload, "site_id")
        object_id = WebhookProcessingService._first_string(payload, "object_id", "device_id", "id")
        event_time = WebhookProcessingService._event_time(payload)
        # Merged in place rather than read-modify-saved. A whole-document save
        # would overwrite whatever a rebuild had computed between this read and
        # this write, projection and revision included. The revision is
        # incremented with the merge, so a rebuild already in flight loses its
        # conditional write and recomputes from these fields instead of
        # replacing them with the copy it read before they arrived.
        #
        # A later delivery of the same audit may be the one carrying the actor
        # or the message, so blanks are filled without overwriting what is known.
        # The audit's own timestamp is the exception: a device event carrying
        # the audit id may have opened the group first, at its own later time.
        await AuditChangeGroup.get_pymongo_collection().update_one(
            {"_id": group.id},
            [
                {
                    "$set": {
                        "receipt_ids": _union("$receipt_ids", [receipt.id]),
                        "actor": _fill(
                            "$actor",
                            WebhookProcessingService._first_string(payload, "admin_name", "admin_id", "user"),
                        ),
                        "method": _fill("$method", WebhookProcessingService._first_string(payload, "method", "src")),
                        "message": _fill("$message", WebhookProcessingService._first_string(payload, "message")),
                        "occurred_at": (
                            event_time
                            if receipt.topic == "audits" and event_time is not None
                            else _fill("$occurred_at", event_time)
                        ),
                        "affected_site_ids": _union("$affected_site_ids", [site_id] if site_id else []),
                        "affected_object_ids": _union("$affected_object_ids", [object_id] if object_id else []),
                        "projection_revision": {"$add": [{"$ifNull": ["$projection_revision", 0]}, 1]},
                        "updated_at": utc_now(),
                    }
                }
            ],
        )

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
