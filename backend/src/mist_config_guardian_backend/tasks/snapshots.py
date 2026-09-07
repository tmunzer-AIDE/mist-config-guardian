"""Celery snapshot tasks."""

import asyncio

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.models.snapshot import SnapshotKind
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.snapshots import SnapshotService
from mist_config_guardian_backend.worker import celery_app


@celery_app.task(name="snapshots.collect")
def collect_snapshot(
    organization_id: str,
    kind: str = SnapshotKind.MANUAL,
    manifest_id: str | None = None,
) -> str:
    """Collect one snapshot in an isolated async database lifecycle."""
    return asyncio.run(_collect_snapshot(organization_id, SnapshotKind(kind), manifest_id))


async def _collect_snapshot(
    organization_id: str,
    kind: SnapshotKind,
    manifest_id: str | None,
) -> str:
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        manifest = await SnapshotService(CredentialVault(settings)).run(
            PydanticObjectId(organization_id),
            kind=kind,
            manifest_id=None if manifest_id is None else PydanticObjectId(manifest_id),
        )
        if manifest.id is None:
            msg = "Snapshot task completed without a manifest identifier"
            raise RuntimeError(msg)
        return str(manifest.id)
    finally:
        await database.close()
