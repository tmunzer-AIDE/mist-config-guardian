"""Celery restore execution tasks."""

import asyncio

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.approvals import expire_pending_approvals
from mist_config_guardian_backend.services.restore_authorization import (
    RestoreAuthorizationService,
)
from mist_config_guardian_backend.services.restore_executor import RestoreExecutor
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="restores.execute", acks_late=False)
def execute_restore(operation_id: str) -> None:
    """Execute one authorized restore without automatic retry."""
    asyncio.run(_execute_restore(operation_id))


async def _execute_restore(operation_id: str) -> None:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        await RestoreExecutor(CredentialVault(settings)).execute(PydanticObjectId(operation_id))
    finally:
        await database.close()


@celery_app.task(name="restores.expire_credentials")
def expire_restore_credentials() -> int:
    """Remove expired delegated Mist credentials from queued work."""
    return asyncio.run(_expire_restore_credentials())


async def _expire_restore_credentials() -> int:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        authorization = RestoreAuthorizationService(settings, CredentialVault(settings), MistVerificationService())
        return await authorization.expire_stale_credentials()
    finally:
        await database.close()


@celery_app.task(name="restores.expire_approvals")
def expire_restore_approvals() -> int:
    """Expire every pending restore approval past its review window."""
    return asyncio.run(_expire_restore_approvals())


async def _expire_restore_approvals() -> int:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        return await expire_pending_approvals()
    finally:
        await database.close()
