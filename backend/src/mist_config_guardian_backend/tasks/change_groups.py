"""Celery tasks that keep change-group projections current."""

import asyncio
import logging

from mist_config_guardian_backend.config import get_settings
from mist_config_guardian_backend.database import DatabaseManager
from mist_config_guardian_backend.models.webhook import AuditChangeGroup
from mist_config_guardian_backend.services.change_groups import ChangeGroupProjector
from mist_config_guardian_backend.worker import celery_app

logger = logging.getLogger(__name__)

BACKFILL_BATCH_SIZE = 200


@celery_app.task(name="change_groups.backfill_projections")
def backfill_change_group_projections() -> int:
    """Fill missing projections and upgrade older network-impact classifications."""
    return asyncio.run(_backfill_change_group_projections())


async def _backfill_change_group_projections() -> int:
    """Rebuild a bounded batch of missing or outdated change-group projections.

    Groups recorded before the projection existed carry none of the display
    data the Changes and Overview pages read, so they would render blank. The
    batch is bounded and the task is idempotent, so a large history is filled in
    over successive runs without ever monopolizing a worker. Policy version 1
    also repairs already-projected administrative changes and unverified SLE
    zero alarms. Raw receipts, versions and monitoring observations are retained.
    """
    settings = get_settings()
    database = DatabaseManager(settings)
    await database.connect()
    try:
        pending = (
            await AuditChangeGroup.find(
                {"$or": [{"projection_updated_at": None}, {"impact_policy_version": {"$ne": 1}}]},
            )
            .sort("-created_at")
            .limit(BACKFILL_BATCH_SIZE)
            .to_list()
        )
        projector = ChangeGroupProjector()
        rebuilt = 0
        for group in pending:
            try:
                await projector.rebuild(group.organization_id, group.audit_id)
            except Exception:
                logger.exception("Unable to project change group %s", group.audit_id)
                continue
            rebuilt += 1
        return rebuilt
    finally:
        await database.close()
