"""Hourly bounded retention maintenance for Guardian records."""

import asyncio

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.services.guardian_retention import maintain_guardian_retention
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="guardian.maintain_retention")
def maintain_retention() -> int:
    return asyncio.run(_maintain())


async def _maintain() -> int:
    database = DatabaseManager(get_settings())
    await database.connect()
    try:
        return await maintain_guardian_retention()
    finally:
        await database.close()
