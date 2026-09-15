"""Fail-closed execution of reviewed restore plans."""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

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
from mist_config_guardian_backend.services.restore_compensation import capture_safety_snapshot
from mist_config_guardian_backend.services.restore_outcome import mark_unconfirmed, terminal_failure_status
from mist_config_guardian_backend.services.restore_planner import (
    RestoreStateStore,
    RestoreVerificationResult,
    SafetySnapshotEntry,
    get_restore_state_store,
    latest_version,
    load_or_build_state,
)
from mist_config_guardian_backend.services.restore_verification import RestoreVerificationService
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    protect_configuration,
    reveal_configuration,
)

logger = logging.getLogger(__name__)

_MAX_REPORTED_CHECKS = 3
_RECORD_ATTEMPTS = 3


class RestoreExecutionError(ValueError):
    """Raised when a plan cannot safely begin execution."""


@dataclass
class _RunOutcome:
    """What one pass over the action list produced."""

    succeeded: bool = True
    id_map: dict[str, str] = field(default_factory=dict)
    applied: dict[int, dict[str, object]] = field(default_factory=dict)


class RestoreExecutor:
    """Execute one plan in persisted dependency order."""

    def __init__(
        self,
        vault: CredentialVault,
        *,
        store: RestoreStateStore | None = None,
        notifications: NotificationService | None = None,
        verifier: RestoreVerificationService | None = None,
    ) -> None:
        self._vault = vault
        self._store = store or get_restore_state_store()
        self._notifications = notifications or NotificationService()
        self._verifier = verifier or RestoreVerificationService(self._store)

    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity.

        Every exit leaves a terminal status, a failure notification when it did
        not complete, and no delegated credential: a worker that stops halfway
        must never leave an operation running with a live session attached.
        """
        operation, organization, token = await self._prepare(operation_id)
        try:
            return await self._run(operation, organization, token)
        except Exception as exc:  # noqa: BLE001 - every exit must end in a terminal, notified state
            await self._fail_unexpectedly(operation, exc)
            return operation
        finally:
            await self._clear_delegated_credential(operation)

    async def _run(self, operation: RestoreOperation, organization: Organization, token: str) -> RestoreOperation:
        """The execution itself; ``execute`` owns the guarantees around it."""
        state = await load_or_build_state(self._store, operation)
        compensating = state.compensates_operation_id is not None
        operation.status = RestoreStatus.RUNNING
        operation.started_at = utc_now()
        operation.touch()
        await operation.save()

        async with MistMutationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            try:
                state.safety_snapshot = await capture_safety_snapshot(
                    client,
                    organization,
                    operation,
                    self._vault,
                    relaxed=compensating,
                )
            except MistMutationError as exc:
                await self._fail_preflight(operation, str(exc))
                await self._notify_failure(operation, str(exc))
                return operation
            await self._store.save(state)

            outcome = await self._run_actions(
                client,
                organization,
                operation,
                snapshot={entry.order: entry for entry in state.safety_snapshot},
            )
            if not outcome.succeeded:
                await self._notify_failure(operation, _failure_reason(operation))
                return operation
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
            await self._fail_verification(operation, verification)
            return operation
        operation.status = RestoreStatus.COMPENSATED if compensating else RestoreStatus.COMPLETED
        operation.touch()
        await operation.save()
        await self._announce_success(operation, state.compensates_operation_id)
        return operation

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

    async def _prepare(
        self,
        operation_id: PydanticObjectId,
    ) -> tuple[RestoreOperation, Organization, str]:
        operation = await RestoreOperation.get(operation_id)
        if operation is None:
            msg = "Restore operation not found"
            raise RestoreExecutionError(msg)
        # The queued status is the idempotency guard: a redelivered task finds a
        # running or finished operation here and refuses to apply it twice.
        if operation.status is not RestoreStatus.QUEUED:
            msg = "Restore operation is not ready to execute"
            raise RestoreExecutionError(msg)
        if (
            operation.encrypted_delegated_credential is None
            or operation.delegated_credential_expires_at is None
            or operation.delegated_credential_expires_at <= utc_now()
        ):
            operation.status = RestoreStatus.FAILED
            operation.encrypted_delegated_credential = None
            operation.delegated_credential_expires_at = None
            operation.preflight_errors.append("Delegated Mist administrator credential expired before execution")
            operation.touch()
            await operation.save()
            await self._notify_failure(operation, "Delegated Mist administrator credential expired before execution")
            msg = "Delegated Mist administrator credential has expired"
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
            reason = "The delegated Mist administrator credential could not be decrypted"
            await self._fail_preflight(operation, reason)
            await self._notify_failure(operation, reason)
            msg = "Delegated Mist administrator credential could not be decrypted"
            raise RestoreExecutionError(msg) from None
        return operation, organization, token

    async def _run_actions(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        *,
        snapshot: dict[int, SafetySnapshotEntry],
    ) -> _RunOutcome:
        outcome = _RunOutcome()
        for index, action in enumerate(operation.actions):
            try:
                payload = await self._execute_action(
                    client,
                    organization,
                    operation,
                    index,
                    outcome.id_map,
                    snapshot=snapshot,
                )
                if payload is not None:
                    outcome.applied[action.order] = payload
            except MistMutationError as exc:
                current = operation.actions[index]
                await self._fail_operation(
                    operation,
                    index,
                    str(exc),
                    action_failed=current.status is not RestoreActionStatus.COMPLETED,
                    outcome_unknown=exc.outcome_unknown and current.status is RestoreActionStatus.EXECUTING,
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
    ) -> None:
        """Refuse to report success while a post-restore check is failing."""
        failed = [check for check in verification.checks if check.status == "failed"]
        listed = "; ".join(check.detail or check.label for check in failed[:_MAX_REPORTED_CHECKS])
        if len(failed) > _MAX_REPORTED_CHECKS:
            listed = f"{listed}; +{len(failed) - _MAX_REPORTED_CHECKS} more"
        reason = f"Post-restore verification failed: {listed}"
        operation.status = terminal_failure_status(operation.actions)
        operation.preflight_errors.append(reason)
        operation.touch()
        await operation.save()
        await self._notify_failure(operation, reason)

    async def _fail_unexpectedly(self, operation: RestoreOperation, exc: Exception) -> None:
        """Close a run that stopped on an error nothing else handled.

        Only the exception type is recorded: an arbitrary exception message can
        carry request or configuration content, which must never be stored or
        logged.
        """
        reason = str(exc) if isinstance(exc, MistMutationError) else f"Restore worker error ({type(exc).__name__})"
        logger.error("restore_execution_aborted operation=%s error_type=%s", operation.id, type(exc).__name__)
        first = mark_unconfirmed(operation.actions, reason)
        if first is not None:
            operation.failure_action_order = first
        operation.status = terminal_failure_status(operation.actions)
        operation.preflight_errors.append(reason)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        try:
            await operation.save()
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

    @staticmethod
    async def _fail_preflight(
        operation: RestoreOperation,
        error: str,
    ) -> None:
        operation.status = RestoreStatus.FAILED
        operation.preflight_errors.append(error)
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.completed_at = utc_now()
        operation.touch()
        await operation.save()

    async def _execute_action(  # noqa: PLR0913 - the pre-write snapshot decides whether a write is still needed
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        index: int,
        id_map: dict[str, str],
        *,
        snapshot: dict[int, SafetySnapshotEntry],
    ) -> dict[str, object] | None:
        action = operation.actions[index]
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        if not definition.supports_restore_action(action.action):
            msg = f"Unsupported {action.action} for {action.scope}:{action.object_type}"
            raise MistMutationError(msg)

        entry = snapshot.get(action.order)
        if action.outcome_unknown and action.action is RestoreActionType.CREATE and entry is not None and entry.existed:
            # The delete this CREATE reverses never happened: the object is
            # still there, and writing it again would duplicate it.
            action.status = RestoreActionStatus.SKIPPED
            operation.actions[index] = action
            operation.touch()
            await operation.save()
            return None

        action.status = RestoreActionStatus.EXECUTING
        operation.actions[index] = action
        operation.touch()
        await operation.save()

        site_id = rewrite_identifier(action.site_mist_id, id_map)
        object_id = rewrite_identifier(action.current_mist_id, id_map)
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
                object_id or action.current_mist_id,
                payload,
                org_id=organization.mist_org_id,
                site_id=site_id,
            )
            action.resulting_mist_id = object_id
        else:
            await client.delete(
                definition,
                object_id or action.current_mist_id,
                org_id=organization.mist_org_id,
                site_id=site_id,
            )

        # The write has happened in Mist: persist that fact before any local
        # bookkeeping can fail, so compensation knows what was applied.
        action.status = RestoreActionStatus.COMPLETED
        operation.actions[index] = action
        operation.touch()
        await operation.save()

        await self._record_result(
            operation,
            action,
            definition.sensitive_fields,
            result or payload,
            site_id=site_id,
        )
        return payload

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

    async def _record_result(
        self,
        operation: RestoreOperation,
        action: RestoreAction,
        sensitive_fields: frozenset[str],
        configuration: dict[str, object],
        *,
        site_id: str | None,
    ) -> None:
        logical = await LogicalObject.get(action.logical_object_id)
        if logical is None or logical.id is None:
            msg = "Restore target logical object no longer exists"
            raise MistMutationError(msg)
        logical_id = logical.id
        deleted = action.action is RestoreActionType.DELETE
        resulting_id = action.resulting_mist_id or action.current_mist_id

        if action.action is RestoreActionType.CREATE:
            previous = (
                await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical_id)
                .sort("-ordinal")
                .first_or_none()
            )
            incarnation = ObjectIncarnation(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                mist_object_id=resulting_id,
                site_mist_id=site_id,
                ordinal=1 if previous is None else previous.ordinal + 1,
            )
            await incarnation.insert()
        else:
            current = await latest_version(logical_id)
            incarnation = None if current is None else await ObjectIncarnation.get(current.incarnation_id)
        if incarnation is None or incarnation.id is None:
            msg = "Restore target incarnation is unavailable"
            raise MistMutationError(msg)
        incarnation_id = incarnation.id

        restored_configuration = dict(configuration)
        if not deleted:
            restored_configuration["id"] = resulting_id

        def build(latest: ObjectVersion) -> ObjectVersion:
            return ObjectVersion(
                organization_id=operation.organization_id,
                logical_object_id=logical_id,
                incarnation_id=incarnation_id,
                version=latest.version + 1,
                event=VersionEvent.RESTORED,
                configuration=(
                    latest.configuration
                    if deleted
                    else protect_configuration(restored_configuration, self._vault, sensitive_fields=sensitive_fields)
                ),
                configuration_hash=(
                    latest.configuration_hash if deleted else configuration_hash(restored_configuration)
                ),
                changed_fields=[],
                references=latest.references if deleted else extract_uuid_references(restored_configuration),
                is_deleted=deleted,
                actor=operation.credential_actor,
            )

        version = await self._insert_next_version(logical_id, build)
        logical.current_mist_id = resulting_id
        logical.site_mist_id = site_id
        logical.current_version = max(logical.current_version, version.version)
        logical.is_deleted = deleted
        logical.touch()
        await logical.save()

    @staticmethod
    async def _fail_operation(
        operation: RestoreOperation,
        action_index: int,
        message: str,
        *,
        action_failed: bool = True,
        outcome_unknown: bool = False,
    ) -> None:
        action = operation.actions[action_index]
        if action_failed:
            action.status = RestoreActionStatus.FAILED
            action.outcome_unknown = outcome_unknown
        action.error = message
        operation.actions[action_index] = action
        operation.failure_action_order = action.order
        operation.status = terminal_failure_status(operation.actions)
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        await operation.save()


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
