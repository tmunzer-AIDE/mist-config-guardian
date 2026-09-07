"""MongoDB and Beanie lifecycle."""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from beanie import init_beanie
from fastapi import FastAPI
from pymongo import AsyncMongoClient

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models import document_models


class DatabaseManager:
    """Own the MongoDB client and application database lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.client: AsyncMongoClient | None = None
        self.ready = not settings.database_enabled

    async def connect(self) -> None:
        """Connect, verify MongoDB, and initialize document models."""
        if not self._settings.database_enabled:
            self.ready = True
            return

        timeout_ms = int(self._settings.mongodb_connect_timeout_seconds * 1000)
        client = AsyncMongoClient(
            self._settings.mongodb_url,
            serverSelectionTimeoutMS=timeout_ms,
            tz_aware=True,
        )
        await client.admin.command("ping")
        database = client[self._settings.mongodb_db_name]
        await init_beanie(database=database, document_models=document_models())
        self.client = client
        self.ready = True

    async def close(self) -> None:
        """Close the MongoDB client."""
        self.ready = False
        if self.client is not None:
            await self.client.close()
            self.client = None


def create_lifespan(settings: Settings) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """Create an application lifespan bound to explicit settings."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        database = DatabaseManager(settings)
        app.state.database = database
        await database.connect()
        try:
            yield
        finally:
            await database.close()

    return lifespan
