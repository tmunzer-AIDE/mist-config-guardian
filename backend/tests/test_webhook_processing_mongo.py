"""Database-backed checks of webhook receipt retries and change-group timing.

Skipped unless ``MONGO_TEST_URL`` names a reachable MongoDB.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from beanie import PydanticObjectId, init_beanie
from kombu.exceptions import OperationalError
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.webhook import AuditChangeGroup, WebhookProcessingStatus, WebhookReceipt
from mist_config_guardian_backend.services import webhooks
from mist_config_guardian_backend.services.webhook_processing import (
    MAX_PROCESSING_ATTEMPTS,
    RETRY_WINDOW,
    STALE_AFTER,
    WebhookProcessingService,
    claim_retryable_receipts,
    retry_delay,
)

MONGO_URL = os.environ.get("MONGO_TEST_URL")
DATABASE = "webhook_processing_records"

pytestmark = [
    pytest.mark.skipif(not MONGO_URL, reason="MONGO_TEST_URL is not set"),
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.usefixtures("database"),
]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def database() -> None:
    client = AsyncMongoClient(MONGO_URL, tz_aware=True)
    await client.drop_database(DATABASE)
    await init_beanie(database=client[DATABASE], document_models=[AuditChangeGroup, WebhookReceipt])
    yield
    await client.drop_database(DATABASE)
    await client.close()


async def _receipt(  # noqa: PLR0913 - each seeded fact is chosen by some test
    status: WebhookProcessingStatus,
    *,
    attempts: int = 0,
    idle: timedelta = timedelta(0),
    age: timedelta | None = None,
    now: datetime,
    topic: str = "audits",
    audit_id: str | None = None,
) -> WebhookReceipt:
    """Store a receipt last touched ``idle`` ago and created ``age`` ago."""
    receipt = WebhookReceipt(
        organization_id=PydanticObjectId(),
        topic=topic,
        event_id=str(PydanticObjectId()),
        audit_id=audit_id,
        payload_hash="hash",
        encrypted_payload="v1:cipher",
        signature_version="v2",
        status=status,
        processing_attempts=attempts,
        created_at=now - (age if age is not None else idle),
        updated_at=now - idle,
    )
    await receipt.insert()
    return receipt


async def test_receipts_due_another_attempt_are_claimed_once() -> None:
    await WebhookReceipt.delete_all()
    now = utc_now()
    second = timedelta(seconds=1)
    due = [
        # The queue was down when it arrived.
        await _receipt(WebhookProcessingStatus.RECEIVED, idle=timedelta(minutes=1), now=now),
        # Its first attempt failed and the first delay has passed.
        await _receipt(WebhookProcessingStatus.FAILED, attempts=1, idle=retry_delay(1) + second, now=now),
        # Its worker died mid-way.
        await _receipt(WebhookProcessingStatus.PROCESSING, attempts=1, idle=STALE_AFTER + second, now=now),
        # Its queue message was lost.
        await _receipt(WebhookProcessingStatus.QUEUED, idle=STALE_AFTER + second, now=now),
    ]
    not_due = [
        await _receipt(WebhookProcessingStatus.FAILED, attempts=1, idle=retry_delay(1) - second, now=now),
        # Each failure doubles the wait.
        await _receipt(WebhookProcessingStatus.FAILED, attempts=2, idle=retry_delay(1) + second, now=now),
        await _receipt(
            WebhookProcessingStatus.FAILED, attempts=MAX_PROCESSING_ATTEMPTS, idle=timedelta(hours=12), now=now
        ),
        await _receipt(WebhookProcessingStatus.PROCESSING, attempts=1, idle=timedelta(minutes=1), now=now),
        await _receipt(WebhookProcessingStatus.QUEUED, idle=timedelta(minutes=1), now=now),
        await _receipt(WebhookProcessingStatus.PROCESSED, attempts=1, idle=timedelta(hours=12), now=now),
        # Today's state would be recorded under an action this old.
        await _receipt(WebhookProcessingStatus.RECEIVED, idle=timedelta(minutes=1), age=RETRY_WINDOW + second, now=now),
    ]

    claimed = await claim_retryable_receipts(now=now)

    assert set(claimed) == {receipt.id for receipt in due}
    for receipt in due:
        stored = await WebhookReceipt.get(receipt.id)
        assert stored is not None
        assert stored.status is WebhookProcessingStatus.QUEUED
    for receipt in not_due:
        stored = await WebhookReceipt.get(receipt.id)
        assert stored is not None
        assert stored.status is receipt.status
    # Claiming touched them, so the next sweep leaves them to the worker.
    assert await claim_retryable_receipts(now=now) == []


async def test_a_receipt_the_queue_refused_is_left_for_the_next_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    await WebhookReceipt.delete_all()
    now = utc_now()
    receipt = await _receipt(WebhookProcessingStatus.QUEUED, now=now)

    def refuse(*_args: object, **_kwargs: object) -> None:
        msg = "broker down"
        raise OperationalError(msg)

    monkeypatch.setattr(webhooks.celery_app, "send_task", refuse)

    assert await webhooks.queue_receipt(receipt.id) is False

    stored = await WebhookReceipt.get(receipt.id)
    assert stored is not None
    assert (stored.status, stored.processing_error) == (WebhookProcessingStatus.RECEIVED, "Worker queue is unavailable")
    assert await claim_retryable_receipts(now=now) == [receipt.id]


async def test_an_audit_after_its_device_events_sets_when_the_change_happened() -> None:
    """A device event carrying the audit id can open the group first, stamped with its own later time."""
    now = utc_now()
    audit_time = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
    device_time = audit_time + timedelta(seconds=40)
    device_event = await _receipt(
        WebhookProcessingStatus.PROCESSING, topic="device-events", audit_id="audit-late", now=now
    )
    audit = WebhookReceipt.model_construct(
        **{**device_event.model_dump(), "id": PydanticObjectId(), "topic": "audits", "event_id": "audit-late"}
    )

    await WebhookProcessingService._add_to_change_group(  # noqa: SLF001
        device_event, {"type": "AP_CONFIGURED", "audit_id": "audit-late", "timestamp": device_time.timestamp()}
    )
    await WebhookProcessingService._add_to_change_group(  # noqa: SLF001
        audit, {"id": "audit-late", "admin_name": "a.osei", "timestamp": audit_time.timestamp()}
    )

    group = await AuditChangeGroup.find_one(
        AuditChangeGroup.organization_id == device_event.organization_id,
        AuditChangeGroup.audit_id == "audit-late",
    )
    assert group is not None
    assert group.occurred_at == audit_time
    assert group.actor == "a.osei"
