"""Hourly bounded impact artifact retention maintenance."""

import asyncio

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.services.investigation_retention import maintain_investigation_retention
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="impact.maintain_retention")
def maintain_retention() -> int:
    return asyncio.run(_maintain())


async def _maintain() -> int:
    database = DatabaseManager(get_settings())
    await database.connect()
    try:
        return await maintain_investigation_retention()
    finally:
        await database.close()
