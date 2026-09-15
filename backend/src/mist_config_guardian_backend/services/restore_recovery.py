"""Close restores whose worker stopped before reaching a terminal state.

Celery runs ``restores.execute`` without redelivery, so a worker lost mid-run
leaves its operation ``RUNNING`` with a live delegated credential attached. The
executor writes progress at least once per action; an operation silent for
longer than the heartbeat timeout has no worker left.
"""

import logging
from datetime import datetime, timedelta

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.notifications import NotificationService
from mist_config_guardian_backend.services.restore_authorization import RestoreAuthorizationService
from mist_config_guardian_backend.services.restore_lease import MongoRestoreLeaseStore, RestoreLeaseStore
from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status
from mist_config_guardian_backend.services.restore_planner import RestoreStateStore, get_restore_state_store

logger = logging.getLogger(__name__)

INTERRUPTED_REASON = "Restore worker interrupted before the run finished; writes in progress are unconfirmed"


class RestoreRecoveryService:
    """Move silent running restores to the same terminal state a crash inside the executor gets."""

    def __init__(  # noqa: PLR0913 - each collaborator is injected separately by tests and the worker task
        self,
        settings: Settings,
        vault: CredentialVault,
        *,
        notifications: NotificationService | None = None,
        authorization: RestoreAuthorizationService | None = None,
        leases: RestoreLeaseStore | None = None,
        store: RestoreStateStore | None = None,
    ) -> None:
        self._settings = settings
        self._notifications = notifications or NotificationService()
        self._authorization = authorization or RestoreAuthorizationService(settings, vault, MistVerificationService())
        self._leases = leases or MongoRestoreLeaseStore()
        self._store = store or get_restore_state_store()

    async def recover_interrupted(self, *, now: datetime | None = None) -> int:
        """Close every running restore whose last progress write is older than the timeout."""
        instant = now or utc_now()
        cutoff = instant - timedelta(minutes=self._settings.restore_worker_heartbeat_timeout_minutes)
        stale = await RestoreOperation.find(
            RestoreOperation.status == RestoreStatus.RUNNING,
            {"updated_at": {"$lte": cutoff}},
        ).to_list()
        recovered = 0
        for operation in stale:
            try:
                if await self._interrupt(operation, instant):
                    recovered += 1
            except Exception as exc:  # noqa: BLE001 - one operation must not hold up the others' recovery
                logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                    "restore_interrupt_failed operation=%s error_type=%s",
                    operation.id,
                    type(exc).__name__,
                )
        return recovered

    async def _interrupt(self, operation: RestoreOperation, now: datetime) -> bool:
        """Close one operation unless its worker wrote progress after it was read."""
        if operation.id is None:
            return False
        encrypted = operation.encrypted_delegated_credential
        observed = operation.updated_at
        compensating = await self._compensating(operation)
        first = mark_unconfirmed(operation.actions, INTERRUPTED_REASON)
        status = terminal_failure_status(operation.actions, compensating=compensating)
        changes: dict[str, object] = {
            "status": status,
            "actions": [action.model_dump() for action in operation.actions],
            "encrypted_delegated_credential": None,
            "delegated_credential_expires_at": None,
            "completed_at": now,
            "updated_at": now,
        }
        if first is not None:
            changes["failure_action_order"] = first
        # Matching the observed heartbeat is the compare-and-set: a worker that
        # wrote progress since the read changes updated_at, and keeps its run.
        result = await RestoreOperation.find_one(
            RestoreOperation.id == operation.id,
            RestoreOperation.status == RestoreStatus.RUNNING,
            RestoreOperation.updated_at == observed,
        ).update({"$set": changes, "$push": {"preflight_errors": INTERRUPTED_REASON}})
        if result is None or result.modified_count != 1:
            return False
        logger.warning("restore_interrupted operation=%s status=%s", operation.id, status)
        # The close is committed, so no follow-up may stop another or escape:
        # an escaping error would lose this notification for good.
        try:
            # Hand the organization back now rather than when the lease lapses.
            # The release only matches this operation's lease, so one another
            # restore already took over is left alone.
            await self._leases.release(operation.organization_id, operation.id)
        except Exception as exc:  # noqa: BLE001 - an unreleased lease lapses on its own; logout and alert must still run
            logger.error(  # noqa: TRY400 - a traceback could carry request content
                "restore_interrupt_lease_release_failed operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )
        try:
            await self._authorization.logout_unused_credential(
                {
                    "_id": operation.id,
                    "organization_id": operation.organization_id,
                    "encrypted_delegated_credential": encrypted,
                }
            )
        except Exception as exc:  # noqa: BLE001 - a failed logout must not cost the notification
            logger.error(  # noqa: TRY400 - a traceback could carry the credential or request content
                "restore_interrupt_logout_failed operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )
        try:
            await self._notifications.notify_restore_failed(
                organization_id=operation.organization_id,
                restore_id=str(operation.id),
                reason=INTERRUPTED_REASON,
            )
        except Exception as exc:  # noqa: BLE001 - the operation is already closed; only the alert is lost
            logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                "restore_interrupt_notification_lost operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )
        return True

    async def _compensating(self, operation: RestoreOperation) -> bool:
        """Whether the silent run is a compensation, which closes failed rather than compensable.

        Plan state that cannot be read must not keep the run open with its
        credential attached, so the close goes ahead as for a restore: that
        keeps whatever the run wrote reversible.
        """
        if operation.id is None:
            return False
        try:
            state = await self._store.load(operation.organization_id, operation.id)
        except Exception as exc:  # noqa: BLE001 - unreadable plan state must not keep a silent run open
            logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                "restore_interrupt_state_unavailable operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )
            return False
        return state is not None and state.compensates_operation_id is not None
