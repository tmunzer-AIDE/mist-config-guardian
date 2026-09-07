"""Celery webhook processing tasks."""

import asyncio

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.webhook_processing import WebhookProcessingService
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
