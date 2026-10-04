"""Celery webhook processing tasks."""

import asyncio

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.webhook_processing import (
    WebhookProcessingService,
    claim_retryable_receipts,
)
from mist_config_guardian_backend.services.webhooks import queue_receipt
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="webhooks.process")
def process_webhook(receipt_id: str) -> None:
    """Process one durable webhook receipt."""
    asyncio.run(_process_webhook(receipt_id))


async def _process_webhook(receipt_id: str) -> None:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        await WebhookProcessingService(CredentialVault(settings)).process(PydanticObjectId(receipt_id))
    finally:
        await database.close()


@celery_app.task(name="webhooks.retry_pending")
def retry_pending_webhooks() -> int:
    """Requeue receipts that failed, never reached the queue, or lost their worker."""
    return asyncio.run(_retry_pending_webhooks())


async def _retry_pending_webhooks() -> int:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        queued = 0
        for receipt_id in await claim_retryable_receipts():
            if await queue_receipt(receipt_id):
                queued += 1
        return queued
    finally:
        await database.close()
