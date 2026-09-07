"""Celery monitoring poll tasks."""

import asyncio

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.monitoring import MonitoringPollService
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="monitoring.poll_active")
def poll_active_monitoring() -> int:
    """Capture one observation for each due monitoring session."""
    return asyncio.run(_poll_active_monitoring())


async def _poll_active_monitoring() -> int:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        return await MonitoringPollService(
            CredentialVault(settings),
            settings,
        ).poll_active()
    finally:
        await database.close()
