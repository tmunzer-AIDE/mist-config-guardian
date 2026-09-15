"""Fail-closed execution of reviewed restore plans."""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist_mutation import (
    MistMutationClient,
    MistMutationError,
)
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import (
    RestoreAction,
    RestoreActionStatus,
    RestoreActionType,
    RestoreOperation,
    RestoreStatus,
)
from mist_config_guardian_backend.models.snapshot import (
    LogicalObject,
    ObjectIncarnation,
    ObjectVersion,
    VersionEvent,
)
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault
from mist_config_guardian_backend.services.notifications import NotificationService
from mist_config_guardian_backend.services.restore_compensation import capture_safety_snapshot, recreated_site_ids
from mist_config_guardian_backend.services.restore_identity import rekey_logical_object
from mist_config_guardian_backend.services.restore_lease import (
    ANOTHER_RESTORE_RUNNING,
    MongoRestoreLeaseStore,
    RestoreLeaseLostError,
    RestoreLeaseStore,
)
from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status
from mist_config_guardian_backend.services.restore_planner import (
    RestoreOperationState,
    RestoreStateStore,
    RestoreVerificationResult,
    SafetySnapshotEntry,
    get_restore_state_store,
    latest_version,
    load_or_build_state,
)
from mist_config_guardian_backend.services.restore_verification import RestoreVerificationService
from mist_config_guardian_backend.services.restore_write_guard import check_before_write
from mist_config_guardian_backend.services.snapshots import SnapshotService
from mist_config_guardian_backend.snapshots.fingerprint import fingerprint, restored_configuration
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import ObjectDefinition, get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    protect_configuration,
    reveal_configuration,
)

logger = logging.getLogger(__name__)

_MAX_REPORTED_CHECKS = 3
_RECORD_ATTEMPTS = 3
# Far inside the janitor's timeout and the lease, so a healthy run never looks
# silent and never loses its organization between two beats.
_HEARTBEAT_INTERVAL_SECONDS = 60.0
# Matches the janitor's default timeout; the worker task passes the configured one.
_LEASE_TTL = timedelta(minutes=15)
_OWNERSHIP_LOST = "Restore operation was closed by another writer"
_LEASE_LOST = "The organization restore lease was lost; no further writes were attempted"


class RestoreExecutionError(ValueError):
    """Raised when a plan cannot safely begin execution."""


class RestoreOwnershipLostError(Exception):
    """Raised when the stored operation is no longer in the state this worker last wrote.

    Deliberately not a ``MistMutationError``: the janitor (or another writer)
    already closed the run, so nothing may record a failure over it.
    """


@dataclass
class _RunOutcome:
    """What one pass over the action list produced."""

    succeeded: bool = True
    id_map: dict[str, str] = field(default_factory=dict)
    applied: dict[int, dict[str, object]] = field(default_factory=dict)


@dataclass
class _RunContext:
    """Plan state one pass over the actions reads and extends.

    The snapshot grows during the pass: an action under a site the plan
    recreates is only recorded right before its write, at the new site.
    """

    state: RestoreOperationState
    snapshot: dict[int, SafetySnapshotEntry]
    recreated_sites: frozenset[str]
    compensating: bool


@dataclass
class _Ownership:
    """The status this worker last wrote for an operation, which every later write must still find.

    ``claimed`` is set by the first guarded write that matches. Only one
    delivery of an operation can achieve that, so only the claimer may clear
    the operation's credential or release its organization lease: a delivery
    that lost the race would otherwise take them from the run that won.
    ``leasing`` marks that the claimer tried to take the lease, which it then
    releases on every exit. ``lost`` names why the worker must stop writing.

    The lock keeps the background heartbeat and the run's own writes from
    interleaving, so a beat never mistakes the worker's own close for a loss.
    """

    status: RestoreStatus
    claimed: bool = False
    leasing: bool = False
    lost: type[RestoreOwnershipLostError | RestoreLeaseLostError] | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _stop_if_lost(ownership: _Ownership) -> None:
    """Refuse every write once the worker learned the run or its organization is no longer its own."""
    if ownership.lost is RestoreLeaseLostError:
        raise RestoreLeaseLostError(_LEASE_LOST)
    if ownership.lost is not None:
        raise RestoreOwnershipLostError(_OWNERSHIP_LOST)


class RestoreExecutor:
    """Execute one plan in persisted dependency order."""

    def __init__(  # noqa: PLR0913 - each collaborator and timing is injected separately by tests and the worker task
        self,
        vault: CredentialVault,
        *,
        store: RestoreStateStore | None = None,
        notifications: NotificationService | None = None,
        verifier: RestoreVerificationService | None = None,
        heartbeat_interval_seconds: float = _HEARTBEAT_INTERVAL_SECONDS,
        leases: RestoreLeaseStore | None = None,
        lease_ttl: timedelta = _LEASE_TTL,
    ) -> None:
        self._vault = vault
        self._store = store or get_restore_state_store()
        self._notifications = notifications or NotificationService()
        self._verifier = verifier or RestoreVerificationService(self._store)
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._leases = leases or MongoRestoreLeaseStore()
        self._lease_ttl = lease_ttl
        self._owned: dict[PydanticObjectId | None, _Ownership] = {}

    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity.

        Every exit leaves a terminal status, a failure notification when it did
        not complete, no delegated credential and no organization lease: a
        worker that stops halfway must never leave an operation running with a
        live session attached, or its organization closed to the next restore.

        The one exception is a delivery that finds the operation claimed by
        another delivery, whether it is no longer queued when loaded or its
        first guarded write is refused: the other delivery owns the run, its
        lease and its credential, so this one leaves all of them untouched. A
        precondition that fails after the queued check is closed like any
        other failure and then re-raised as ``RestoreExecutionError``, so the
        task still records that the restore never started.

        A run that finds its operation closed by another writer, normally the
        janitor after this worker went silent, or its organization lease gone,
        stops where it is: the closer recorded the terminal state and notified,
        or the janitor will once the run is silent, and one more write from
        this worker could undo that or interleave with the restore now running.
        """
        operation = await self._load_queued(operation_id)
        ownership = _Ownership(status=operation.status)
        self._owned[operation.id] = ownership
        compensating = False
        try:
            organization, token = await self._prepare(operation)
            state = await load_or_build_state(self._store, operation)
            # Known before anything can fail after a write: a compensation that
            # stops ends failed, where a restore that stops stays compensable.
            compensating = state.compensates_operation_id is not None
            return await self._run(operation, organization, token, state)
        except RestoreLeaseLostError as exc:
            logger.warning("restore_lease_lost operation=%s error_type=%s", operation.id, type(exc).__name__)
            return operation
        except RestoreOwnershipLostError as exc:
            logger.warning("restore_ownership_lost operation=%s error_type=%s", operation.id, type(exc).__name__)
            return operation
        except RestoreExecutionError as exc:
            await self._close_failed(operation, str(exc), compensating=compensating)
            raise
        except Exception as exc:  # noqa: BLE001 - every exit must end in a terminal, notified state
            await self._fail_unexpectedly(operation, exc, compensating=compensating)
            return operation
        finally:
            if ownership.claimed:
                await self._clear_delegated_credential(operation)
            if ownership.leasing:
                await self._release_lease(operation)
            self._owned.pop(operation.id, None)

    async def _run(
        self,
        operation: RestoreOperation,
        organization: Organization,
        token: str,
        state: RestoreOperationState,
    ) -> RestoreOperation:
        """Claim the queued operation, take its organization, then keep both alive for as long as the run lasts.

        The claim comes before the lease, so a delivery that loses the claim
        never touches the lease the winner holds. Nothing reads or writes Mist
        until the lease is held, so two restores of one organization never
        overlap: a claimed run that finds another one ahead of it closes itself.

        The background beat covers phases with no write of their own, such as a
        safety snapshot or a verification over many objects, which could
        otherwise outlast the janitor's timeout and the lease on a healthy run.
        """
        operation.status = RestoreStatus.RUNNING
        operation.started_at = utc_now()
        operation.touch()
        await self._persist(operation)
        if not await self._acquire_lease(operation):
            await self._refuse_busy_organization(operation, organization, token)
            return operation
        beat = asyncio.create_task(self._beat_until_cancelled(operation))
        try:
            return await self._run_owned(operation, organization, token, state)
        finally:
            beat.cancel()
            await asyncio.gather(beat, return_exceptions=True)

    async def _run_owned(
        self,
        operation: RestoreOperation,
        organization: Organization,
        token: str,
        state: RestoreOperationState,
    ) -> RestoreOperation:
        """The execution itself; ``execute`` owns the guarantees around it."""
        compensating = state.compensates_operation_id is not None
        async with MistMutationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            try:
                state.safety_snapshot = await capture_safety_snapshot(client, organization, operation, self._vault)
            except MistMutationError as exc:
                await self._fail_preflight(operation, str(exc))
                await self._notify_failure(operation, str(exc))
                return operation
            await self._store.save(state)
            await self._heartbeat(operation)

            context = _RunContext(
                state=state,
                snapshot={entry.order: entry for entry in state.safety_snapshot},
                recreated_sites=recreated_site_ids(operation.actions),
                compensating=compensating,
            )
            outcome = await self._run_actions(client, organization, operation, context)
            if not outcome.succeeded:
                await self._notify_failure(operation, _failure_reason(operation))
                return operation
            await self._heartbeat(operation)
            verification = await self._verifier.verify(
                client,
                organization,
                operation,
                id_map=outcome.id_map,
                applied=outcome.applied,
            )

        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.completed_at = utc_now()
        if not verification.verified:
            await self._fail_verification(operation, verification, compensating=compensating)
            return operation
        operation.status = RestoreStatus.COMPENSATED if compensating else RestoreStatus.COMPLETED
        operation.touch()
        await self._persist(operation)
        await self._announce_success(operation, state.compensates_operation_id)
        return operation

    def _ownership_of(self, operation: RestoreOperation) -> _Ownership:
        """What this worker last wrote; an operation it never claimed is taken to be running."""
        return self._owned.setdefault(operation.id, _Ownership(status=RestoreStatus.RUNNING))

    async def _persist(self, operation: RestoreOperation) -> None:
        """Write the worker's copy, but only over the state this worker last wrote.

        A whole-document save would silently undo the janitor closing this run:
        the status would read running again and the credential would return.
        Matching the last written status turns that into a refused write.
        """
        if operation.id is None:
            # Nothing addressable, so nothing another writer could have closed.
            await operation.save()
            self._ownership_of(operation).claimed = True
            return
        ownership = self._ownership_of(operation)
        async with ownership.lock:
            _stop_if_lost(ownership)
            result = await RestoreOperation.find_one(
                RestoreOperation.id == operation.id,
                RestoreOperation.status == ownership.status,
            ).update({"$set": operation.model_dump(exclude={"id", "revision_id"})})
            if result is None or result.matched_count == 0:
                ownership.lost = RestoreOwnershipLostError
                raise RestoreOwnershipLostError(_OWNERSHIP_LOST)
            ownership.status = operation.status
            ownership.claimed = True

    async def _heartbeat(self, operation: RestoreOperation) -> None:
        """Renew the organization lease and record that this worker is still alive.

        The lease is renewed first: a worker that lost it must stop, and must
        not refresh the timestamp that lets the janitor close its silent run.
        Only the timestamp is written, and only while the stored run is still
        running: a heartbeat must neither overwrite what other writers set nor
        revive a run the janitor already closed.
        """
        ownership = self._ownership_of(operation)
        async with ownership.lock:
            _stop_if_lost(ownership)
            if ownership.status is not RestoreStatus.RUNNING or operation.id is None:
                return
            if not await self._leases.renew(operation.organization_id, operation.id, ttl=self._lease_ttl):
                ownership.lost = RestoreLeaseLostError
                raise RestoreLeaseLostError(_LEASE_LOST)
            now = utc_now()
            result = await RestoreOperation.find_one(
                RestoreOperation.id == operation.id,
                RestoreOperation.status == RestoreStatus.RUNNING,
            ).update({"$set": {"updated_at": now}})
            if result is None or result.matched_count == 0:
                ownership.lost = RestoreOwnershipLostError
                raise RestoreOwnershipLostError(_OWNERSHIP_LOST)
            operation.updated_at = now

    async def _beat_until_cancelled(self, operation: RestoreOperation) -> None:
        """Heartbeat on a fixed interval until the run ends or the operation is no longer this worker's.

        A lost operation or lease is only recorded here: the run's next write
        refuses, and ``execute`` stops it without touching what others store.
        """
        while True:
            await asyncio.sleep(self._heartbeat_interval_seconds)
            try:
                await self._heartbeat(operation)
            except RestoreLeaseLostError:
                logger.warning("restore_heartbeat_lease_lost operation=%s", operation.id)
                return
            except RestoreOwnershipLostError:
                logger.warning("restore_heartbeat_ownership_lost operation=%s", operation.id)
                return
            except Exception as exc:  # noqa: BLE001 - a failed beat is retried on the next interval
                logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                    "restore_heartbeat_failed operation=%s error_type=%s",
                    operation.id,
                    type(exc).__name__,
                )

    async def _announce_success(
        self,
        operation: RestoreOperation,
        compensates_operation_id: PydanticObjectId | None,
    ) -> None:
        """Run the follow-ups of a persisted success without ever undoing it.

        Mist already holds the restored configuration and the success status is
        saved, so a failing follow-up is logged rather than rewritten into a
        failed, compensable restore.
        """
        if compensates_operation_id is not None:
            try:
                await self._mark_compensated(operation.organization_id, compensates_operation_id)
            except Exception as exc:  # noqa: BLE001 - a persisted success must not be reopened
                logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                    "restore_compensated_mark_failed operation=%s error_type=%s",
                    operation.id,
                    type(exc).__name__,
                )
        try:
            await self._notifications.notify_restore_completed(
                organization_id=operation.organization_id,
                restore_id=str(operation.id),
                applied_count=sum(1 for action in operation.actions if action.status is RestoreActionStatus.COMPLETED),
            )
        except Exception as exc:  # noqa: BLE001 - a persisted success must not be reopened
            logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                "restore_completed_notification_lost operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )

    @staticmethod
    async def _load_queued(operation_id: PydanticObjectId) -> RestoreOperation:
        """Load the operation to run, refusing one that another delivery already claimed.

        Nothing here may change the operation: a redelivered task that finds it
        running or finished must leave its status, notifications and credential
        to the run that owns it.
        """
        operation = await RestoreOperation.get(operation_id)
        if operation is None:
            msg = "Restore operation not found"
            raise RestoreExecutionError(msg)
        # The queued status is the idempotency guard: a redelivered task finds a
        # running or finished operation here and refuses to apply it twice.
        if operation.status is not RestoreStatus.QUEUED:
            msg = "Restore operation is not ready to execute"
            raise RestoreExecutionError(msg)
        return operation

    async def _prepare(self, operation: RestoreOperation) -> tuple[Organization, str]:
        """Resolve what the run needs, raising ``RestoreExecutionError`` with a storable reason.

        The caller closes the operation on that error, so each message is fixed
        text: it becomes the recorded reason and the failure notification.
        """
        if (
            operation.encrypted_delegated_credential is None
            or operation.delegated_credential_expires_at is None
            or operation.delegated_credential_expires_at <= utc_now()
        ):
            msg = "Delegated Mist administrator credential expired before execution"
            raise RestoreExecutionError(msg)

        organization = await Organization.get(operation.organization_id)
        if organization is None:
            msg = "Restore organization not found"
            raise RestoreExecutionError(msg)
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise RestoreExecutionError(msg)

        try:
            token = self._vault.decrypt_for_context(
                operation.encrypted_delegated_credential,
                context=f"restore:{operation.id}",
            )
        except CredentialDecryptionError:
            msg = "Delegated Mist administrator credential could not be decrypted"
            raise RestoreExecutionError(msg) from None
        return organization, token

    async def _run_actions(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        context: _RunContext,
    ) -> _RunOutcome:
        outcome = _RunOutcome()
        for index, action in enumerate(operation.actions):
            await self._heartbeat(operation)
            try:
                payload = await self._execute_action(
                    client,
                    organization,
                    operation,
                    index,
                    outcome.id_map,
                    context,
                )
                if payload is not None:
                    outcome.applied[action.order] = payload
            except MistMutationError as exc:
                current = operation.actions[index]
                # A write Mist may have applied without saying so, or accepted
                # but did not show as done, is unconfirmed either way: whether
                # it happened is for compensation to find out from live state.
                unconfirmed = exc.outcome_unknown and current.status in {
                    RestoreActionStatus.EXECUTING,
                    RestoreActionStatus.COMPLETED,
                }
                await self._fail_operation(
                    operation,
                    index,
                    str(exc),
                    action_failed=current.status is not RestoreActionStatus.COMPLETED or unconfirmed,
                    outcome_unknown=unconfirmed,
                    compensating=context.compensating,
                )
                outcome.succeeded = False
                return outcome
        return outcome

    async def _notify_failure(self, operation: RestoreOperation, reason: str) -> None:
        await self._notifications.notify_restore_failed(
            organization_id=operation.organization_id,
            restore_id=str(operation.id),
            reason=reason,
        )

    async def _fail_verification(
        self,
        operation: RestoreOperation,
        verification: RestoreVerificationResult,
        *,
        compensating: bool = False,
    ) -> None:
        """Refuse to report success while a post-restore check is failing."""
        failed = [check for check in verification.checks if check.status == "failed"]
        listed = "; ".join(check.detail or check.label for check in failed[:_MAX_REPORTED_CHECKS])
        if len(failed) > _MAX_REPORTED_CHECKS:
            listed = f"{listed}; +{len(failed) - _MAX_REPORTED_CHECKS} more"
        reason = f"Post-restore verification failed: {listed}"
        operation.status = terminal_failure_status(operation.actions, compensating=compensating)
        operation.preflight_errors.append(reason)
        operation.touch()
        await self._persist(operation)
        await self._notify_failure(operation, reason)

    async def _fail_unexpectedly(
        self,
        operation: RestoreOperation,
        exc: Exception,
        *,
        compensating: bool = False,
    ) -> None:
        """Close a run that stopped on an error nothing else handled.

        Only the exception type is recorded: an arbitrary exception message can
        carry request or configuration content, which must never be stored or
        logged.
        """
        reason = str(exc) if isinstance(exc, MistMutationError) else f"Restore worker error ({type(exc).__name__})"
        logger.error("restore_execution_aborted operation=%s error_type=%s", operation.id, type(exc).__name__)
        await self._close_failed(operation, reason, compensating=compensating)

    async def _close_failed(self, operation: RestoreOperation, reason: str, *, compensating: bool = False) -> None:
        """Record a terminal failure and notify exactly once, even while storage or notifications fail.

        Shared by failed preconditions, a busy organization and unexpected
        errors, so every exit that nothing more specific handled leaves the
        same terminal, credential-free state; ``execute`` still clears the
        credential with its own write.
        """
        first = mark_unconfirmed(operation.actions, reason)
        if first is not None:
            operation.failure_action_order = first
        operation.status = terminal_failure_status(operation.actions, compensating=compensating)
        operation.preflight_errors.append(reason)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        try:
            await self._persist(operation)
        except RestoreLeaseLostError:
            # Another restore holds the organization; the janitor closes this silent run and notifies.
            logger.warning("restore_lease_lost operation=%s", operation.id)
            return
        except RestoreOwnershipLostError:
            # Another writer closed the run and notified; a second close would overwrite it.
            logger.warning("restore_ownership_lost operation=%s", operation.id)
            return
        except Exception as save_error:  # noqa: BLE001 - the janitor recovers an unsaved terminal state
            logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                "restore_terminal_state_unsaved operation=%s error_type=%s",
                operation.id,
                type(save_error).__name__,
            )
        try:
            await self._notify_failure(operation, reason)
        except Exception as notify_error:  # noqa: BLE001 - a lost notification must not mask the failure
            logger.error(  # noqa: TRY400 - a traceback could carry configuration content
                "restore_failure_notification_lost operation=%s error_type=%s",
                operation.id,
                type(notify_error).__name__,
            )

    @staticmethod
    async def _clear_delegated_credential(operation: RestoreOperation) -> None:
        """Remove the delegated credential with a field-scoped write, whatever else failed."""
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        if operation.id is None:
            return
        try:
            await RestoreOperation.find_one(RestoreOperation.id == operation.id).update(
                {"$set": {"encrypted_delegated_credential": None, "delegated_credential_expires_at": None}}
            )
        except Exception as exc:  # noqa: BLE001 - the janitor and expiry job retry the clear
            logger.error(  # noqa: TRY400 - a traceback could carry the credential write
                "restore_credential_clear_failed operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )

    async def _acquire_lease(self, operation: RestoreOperation) -> bool:
        """Take the organization for the claimed run; ``execute`` releases it on every exit from here on.

        The attempt is recorded before the call, so a lease the store granted
        just before an error is still released. Releasing is safe even then:
        only the claimer of this operation ever holds a lease in its name.
        """
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise RestoreExecutionError(msg)
        self._ownership_of(operation).leasing = True
        return await self._leases.acquire(operation.organization_id, operation.id, ttl=self._lease_ttl)

    async def _release_lease(self, operation: RestoreOperation) -> None:
        """Hand the organization back whatever else failed; an unreleased lease lapses on its own.

        The release matches only this operation's lease, so a worker whose
        lease another restore took over removes nothing.
        """
        if operation.id is None:
            return
        try:
            await self._leases.release(operation.organization_id, operation.id)
        except Exception as exc:  # noqa: BLE001 - the TTL index removes a lease nobody released
            logger.error(  # noqa: TRY400 - a traceback could carry request content
                "restore_lease_release_failed operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )

    async def _refuse_busy_organization(
        self,
        operation: RestoreOperation,
        organization: Organization,
        token: str,
    ) -> None:
        """Close a claimed run that another restore of the organization is ahead of, before any Mist call.

        This worker owns the run, so it records and announces the failure like
        any other, then logs out the session it will never use.
        """
        await self._close_failed(operation, ANOTHER_RESTORE_RUNNING)
        if self._ownership_of(operation).lost is not None:
            return
        try:
            # Leaving the client logs a session credential out of Mist.
            async with MistMutationClient(token=token, region=organization.cloud_region):
                pass
        except Exception as exc:  # noqa: BLE001 - the session expires on its own; the close is recorded
            logger.error(  # noqa: TRY400 - a traceback could carry the credential or request content
                "restore_refused_logout_failed operation=%s error_type=%s",
                operation.id,
                type(exc).__name__,
            )

    @staticmethod
    async def _mark_compensated(
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
    ) -> None:
        await RestoreOperation.find_one(
            RestoreOperation.id == operation_id,
            RestoreOperation.organization_id == organization_id,
        ).update(
            {
                "$set": {
                    "status": RestoreStatus.COMPENSATED,
                    "updated_at": utc_now(),
                }
            }
        )

    async def _fail_preflight(
        self,
        operation: RestoreOperation,
        error: str,
    ) -> None:
        operation.status = RestoreStatus.FAILED
        operation.preflight_errors.append(error)
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.completed_at = utc_now()
        operation.touch()
        await self._persist(operation)

    async def _execute_action(  # noqa: PLR0913, PLR0917 - the pass state travels with the action
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        index: int,
        id_map: dict[str, str],
        context: _RunContext,
    ) -> dict[str, object] | None:
        action = operation.actions[index]
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        if not definition.supports_restore_action(action.action):
            msg = f"Unsupported {action.action} for {action.scope}:{action.object_type}"
            raise MistMutationError(msg)

        # Remapped first, so an object under a site recreated earlier in this
        # pass is read, written and read back where it now lives.
        site_id, object_id = remap_target(action, id_map)
        check = await check_before_write(
            client,
            organization,
            self._vault,
            action,
            definition,
            object_id=object_id,
            site_id=site_id,
            entry=context.snapshot.get(action.order),
            deferred=action.site_mist_id is not None and action.site_mist_id in context.recreated_sites,
            compensating=context.compensating,
        )
        if check.recorded:
            # Stored before the write, so compensation can undo it even if the
            # worker stops right after Mist applies it.
            context.snapshot[action.order] = check.entry
            context.state.safety_snapshot.append(check.entry)
            await self._store.save(context.state)
        if check.skip:
            # A reversal with nothing left to write: the object is already
            # where it would leave it, and writing again could only duplicate
            # or churn it. Skipped, so it never counts as applied.
            action.status = RestoreActionStatus.SKIPPED
            operation.actions[index] = action
            operation.touch()
            await self._persist(operation)
            return None

        # Guarded, so an operation the janitor closed never reaches Mist again.
        action.status = RestoreActionStatus.EXECUTING
        operation.actions[index] = action
        operation.touch()
        await self._persist(operation)

        configuration = reveal_configuration(action.protected_configuration, self._vault)
        payload = prepare_restore_payload(
            configuration,
            excluded_fields=definition.restore_excluded_fields,
            id_map=id_map,
        )

        result: dict[str, object] | None = None
        if action.action is RestoreActionType.CREATE:
            result = await client.create(
                definition,
                payload,
                org_id=organization.mist_org_id,
                site_id=site_id,
            )
            resulting_id = result.get("id")
            if not isinstance(resulting_id, str) or not resulting_id:
                # Mist accepted the create, so the object may exist without an id
                # to target: it stays possibly applied, never "not attempted".
                msg = f"Mist did not return an id for created {action.object_type}"
                raise MistMutationError(msg, outcome_unknown=True)
            action.resulting_mist_id = resulting_id
            id_map[action.current_mist_id] = resulting_id
        elif action.action is RestoreActionType.UPDATE:
            result = await client.update(
                definition,
                object_id,
                payload,
                org_id=organization.mist_org_id,
                site_id=site_id,
            )
            action.resulting_mist_id = object_id
        else:
            await client.delete(
                definition,
                object_id,
                org_id=organization.mist_org_id,
                site_id=site_id,
            )

        # The write has happened in Mist: persist that fact before any local
        # bookkeeping can fail, so compensation knows what was applied. If the
        # janitor closed the run meanwhile, this is refused and its FAILED,
        # unconfirmed record of the write stands, which is still compensable.
        action.status = RestoreActionStatus.COMPLETED
        operation.actions[index] = action
        operation.touch()
        await self._persist(operation)

        readback = await self._read_back(client, organization, action, definition, object_id=object_id, site_id=site_id)
        # The digest the collector will store for this same response, so the
        # reversal's expected state and the restored version agree with it.
        action.applied_hash = None if readback is None else fingerprint(definition, readback)
        operation.actions[index] = action
        operation.touch()
        await self._persist(operation)

        # The payload, not Mist's answer: it holds the real value of any secret
        # the read-back masks.
        await self._record_result(operation, action, definition, payload, readback=readback, site_id=site_id)
        return payload

    @staticmethod
    async def _read_back(  # noqa: PLR0913 - the remapped identifiers are what the write targeted
        client: MistMutationClient,
        organization: Organization,
        action: RestoreAction,
        definition: ObjectDefinition,
        *,
        object_id: str,
        site_id: str | None,
    ) -> dict[str, object] | None:
        """Read the written object back from Mist before trusting the write (spec §9.5.5).

        A write Mist accepted but does not show is not a success: the run
        stops there, with the write already recorded as applied, so it stays
        compensable. A delete Mist accepted may still take effect, so it is
        reported as unconfirmed: compensation then recreates the object only
        if it is gone. The error names the object, never what was read.
        """
        target = (
            action.resulting_mist_id
            if action.action is RestoreActionType.CREATE and action.resulting_mist_id
            else object_id
        )
        current = await client.get_current(definition, target, org_id=organization.mist_org_id, site_id=site_id)
        if action.action is RestoreActionType.DELETE:
            if current is not None:
                msg = f"{action.object_name} still exists in Mist after the delete"
                raise MistMutationError(msg, outcome_unknown=True)
            return None
        if current is None:
            msg = f"{action.object_name} was not found in Mist after the write"
            raise MistMutationError(msg)
        return current

    @staticmethod
    async def _insert_next_version(
        logical_id: PydanticObjectId,
        build: Callable[[ObjectVersion], ObjectVersion],
    ) -> ObjectVersion:
        """Append a version after the newest one, re-reading if another writer took the number."""
        for attempt in range(1, _RECORD_ATTEMPTS + 1):
            latest = await latest_version(logical_id)
            if latest is None:
                msg = "Restore target has no source history"
                raise MistMutationError(msg)
            version = build(latest)
            try:
                await version.insert()
            except DuplicateKeyError:
                if attempt == _RECORD_ATTEMPTS:
                    raise
                continue
            return version
        msg = "Restore target history could not be extended"
        raise MistMutationError(msg)

    async def _record_result(  # noqa: PLR0913 - the write, its read-back, and where it landed
        self,
        operation: RestoreOperation,
        action: RestoreAction,
        definition: ObjectDefinition,
        written: dict[str, object],
        *,
        readback: dict[str, object] | None,
        site_id: str | None,
    ) -> None:
        """Append the restored version under the identity the next capture will look for.

        The id comes from the read-back, derived exactly as the collector
        derives it from the same response, and the source key moves with it:
        otherwise a recreated object, or anything written under a recreated
        site, would start a second history on the next backup.

        The version records what the next capture of the same response would:
        its digest is the collector's digest of the read-back, masks included,
        and its configuration is the read-back with each masked secret filled
        from ``written``, so it stays replayable.

        The identity moves first. A capture that raced the restore is folded in
        beneath the restored version, which stays the latest, and a key another
        identity owns stops the restore before anything is recorded.
        """
        logical = await LogicalObject.get(action.logical_object_id)
        if logical is None or logical.id is None:
            msg = "Restore target logical object no longer exists"
            raise MistMutationError(msg)
        logical_id = logical.id
        deleted = action.action is RestoreActionType.DELETE
        if not deleted and readback is None:
            msg = f"{action.object_name} has no read-back to record"
            raise MistMutationError(msg)
        object_id = action.resulting_mist_id or action.current_mist_id
        if readback is not None:
            object_id = SnapshotService.object_id(readback, definition, site_id)
        opened: list[PydanticObjectId] = []

        async def incarnation() -> PydanticObjectId:
            if not opened:
                opened.append(
                    await self._incarnation_for(operation, logical_id, action, object_id=object_id, site_id=site_id)
                )
            return opened[0]

        if not deleted:
            source_key = SnapshotService.source_key(definition, site_id, object_id)
            if source_key != logical.source_key:
                await rekey_logical_object(
                    logical,
                    source_key=source_key,
                    restore_started_at=operation.started_at,
                    incarnation=incarnation,
                )
        incarnation_id = await incarnation()
        protected = (
            None
            if readback is None
            else protect_configuration(
                restored_configuration(definition, readback, written),
                self._vault,
                sensitive_fields=definition.sensitive_fields,
            )
        )

        def build(latest: ObjectVersion) -> ObjectVersion:
            return ObjectVersion(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.RESTORED,
                configuration=latest.configuration if protected is None else protected,
                configuration_hash=(
                    latest.configuration_hash if readback is None else fingerprint(definition, readback)
                ),
                changed_fields=[],
                references=latest.references if readback is None else extract_uuid_references(readback),
                is_deleted=deleted,
                actor=operation.credential_actor,
            )

        version = await self._insert_next_version(logical_id, build)
        logical.current_mist_id = object_id
        logical.site_mist_id = site_id
        logical.current_version = max(logical.current_version, version.version)
        logical.is_deleted = deleted
        logical.touch()
        await logical.save()

    @staticmethod
    async def _incarnation_for(
        operation: RestoreOperation,
        logical_id: PydanticObjectId,
        action: RestoreAction,
        *,
        object_id: str,
        site_id: str | None,
    ) -> PydanticObjectId:
        """Reuse the incarnation the collector would match, opening one only for an object back under a new id.

        The collector matches an incarnation by logical object and Mist id,
        never by site, so an update does too: incarnations recorded before the
        site was stored carry none, and comparing it would open a duplicate on
        every restore. A delete ends the current incarnation.
        """
        current = (
            await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical_id)
            .sort("-ordinal")
            .first_or_none()
        )
        if action.action is RestoreActionType.DELETE and current is not None and current.id is not None:
            return current.id
        if action.action is RestoreActionType.UPDATE:
            matching = (
                await ObjectIncarnation.find(
                    ObjectIncarnation.logical_object_id == logical_id,
                    ObjectIncarnation.mist_object_id == object_id,
                )
                .sort("-ordinal")
                .first_or_none()
            )
            if matching is not None and matching.id is not None:
                return matching.id
        incarnation = ObjectIncarnation(
            organization_id=operation.organization_id,
            logical_object_id=logical_id,
            mist_object_id=object_id,
            site_mist_id=site_id,
            ordinal=1 if current is None else current.ordinal + 1,
        )
        await incarnation.insert()
        if incarnation.id is None:
            msg = "Restore target incarnation is unavailable"
            raise MistMutationError(msg)
        return incarnation.id

    async def _fail_operation(  # noqa: PLR0913 - the failed action's outcome and the run's kind are separate facts
        self,
        operation: RestoreOperation,
        action_index: int,
        message: str,
        *,
        action_failed: bool = True,
        outcome_unknown: bool = False,
        compensating: bool = False,
    ) -> None:
        action = operation.actions[action_index]
        if action_failed:
            action.status = RestoreActionStatus.FAILED
            action.outcome_unknown = outcome_unknown
        action.error = message
        operation.actions[action_index] = action
        operation.failure_action_order = action.order
        operation.status = terminal_failure_status(operation.actions, compensating=compensating)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        await self._persist(operation)


def _failure_reason(operation: RestoreOperation) -> str:
    """Describe why a run stopped, for the mandatory failure notification."""
    for action in operation.actions:
        if action.error:
            return f"{action.object_name}: {action.error}"
    return "Restore execution stopped before completing every action"


def prepare_restore_payload(
    configuration: dict[str, object],
    *,
    excluded_fields: frozenset[str],
    id_map: dict[str, str],
) -> dict[str, object]:
    """Remove server fields and rewrite every known regenerated UUID."""
    return {key: rewrite_value(value, id_map) for key, value in configuration.items() if key not in excluded_fields}


def rewrite_value(value: object, id_map: dict[str, str]) -> object:
    """Recursively rewrite exact identifier values."""
    if isinstance(value, dict):
        return {str(key): rewrite_value(child, id_map) for key, child in value.items()}
    if isinstance(value, list):
        return [rewrite_value(child, id_map) for child in value]
    if isinstance(value, str):
        return id_map.get(value, value)
    return value


def rewrite_identifier(value: str | None, id_map: dict[str, str]) -> str | None:
    """Rewrite an optional object or site identifier."""
    return None if value is None else id_map.get(value, value)


def remap_target(action: RestoreAction, id_map: dict[str, str]) -> tuple[str | None, str]:
    """Return the site and object ids an action addresses once earlier recreations are applied.

    A changed site is recorded on the action before anything is written, so
    verification and compensation address the object at the new site even if
    the run stops right after this write.
    """
    site_id = rewrite_identifier(action.site_mist_id, id_map)
    object_id = rewrite_identifier(action.current_mist_id, id_map) or action.current_mist_id
    if site_id != action.site_mist_id:
        action.resulting_site_mist_id = site_id
    return site_id, object_id
