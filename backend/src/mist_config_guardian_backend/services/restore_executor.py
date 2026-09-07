"""Fail-closed execution of reviewed restore plans."""

from beanie import PydanticObjectId

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
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.snapshots.canonical import configuration_hash
from mist_config_guardian_backend.snapshots.references import extract_uuid_references
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import (
    protect_configuration,
    reveal_configuration,
)


class RestoreExecutionError(ValueError):
    """Raised when a plan cannot safely begin execution."""


class RestoreExecutor:
    """Execute one plan in persisted dependency order."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def execute(self, operation_id: PydanticObjectId) -> RestoreOperation:
        """Execute pending actions once using the delegated Mist identity."""
        operation, organization, token = await self._prepare(operation_id)
        operation.status = RestoreStatus.RUNNING
        operation.started_at = utc_now()
        operation.touch()
        await operation.save()

        async with MistMutationClient(
            token=token,
            region=organization.cloud_region,
        ) as client:
            try:
                await self._validate_live_state(client, organization, operation)
            except MistMutationError as exc:
                await self._fail_preflight(operation, str(exc))
                return operation
            if not await self._run_actions(client, organization, operation):
                return operation

        operation.status = RestoreStatus.COMPLETED
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        await operation.save()
        return operation

    async def _prepare(
        self,
        operation_id: PydanticObjectId,
    ) -> tuple[RestoreOperation, Organization, str]:
        operation = await RestoreOperation.get(operation_id)
        if operation is None:
            msg = "Restore operation not found"
            raise RestoreExecutionError(msg)
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
            msg = "Delegated Mist administrator credential has expired"
            raise RestoreExecutionError(msg)

        organization = await Organization.get(operation.organization_id)
        if organization is None:
            msg = "Restore organization not found"
            raise RestoreExecutionError(msg)
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise RestoreExecutionError(msg)

        token = self._vault.decrypt_for_context(
            operation.encrypted_delegated_credential,
            context=f"restore:{operation.id}",
        )
        return operation, organization, token

    async def _run_actions(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
    ) -> bool:
        id_map: dict[str, str] = {}
        for index, action in enumerate(operation.actions):
            if action.status is RestoreActionStatus.COMPLETED:
                if action.resulting_mist_id:
                    id_map[action.current_mist_id] = action.resulting_mist_id
                continue
            try:
                await self._execute_action(
                    client,
                    organization,
                    operation,
                    index,
                    id_map,
                )
            except MistMutationError as exc:
                await self._fail_operation(operation, index, str(exc))
                return False
        return True

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

    @staticmethod
    async def _validate_live_state(
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
    ) -> None:
        """Abort before writes when live state differs from the reviewed plan."""
        for action in operation.actions:
            definition = get_definition(action.scope, action.object_type)
            if definition is None:
                msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
                raise MistMutationError(msg)
            current = await client.get_current(
                definition,
                action.current_mist_id,
                org_id=organization.mist_org_id,
                site_id=action.site_mist_id,
            )
            if action.action is RestoreActionType.CREATE:
                if current is not None:
                    msg = f"{action.object_name} was recreated after this plan was reviewed"
                    raise MistMutationError(msg)
                continue
            if action.expected_current_hash is None:
                if current is not None:
                    msg = f"{action.object_name} was recreated after this plan was reviewed"
                    raise MistMutationError(msg)
                continue
            if current is None:
                msg = f"{action.object_name} no longer exists"
                raise MistMutationError(msg)
            current_hash = configuration_hash(
                current,
                ignored_fields=definition.ignored_fields,
            )
            if current_hash != action.expected_current_hash:
                msg = f"{action.object_name} changed after this plan was reviewed"
                raise MistMutationError(msg)

    async def _execute_action(
        self,
        client: MistMutationClient,
        organization: Organization,
        operation: RestoreOperation,
        index: int,
        id_map: dict[str, str],
    ) -> None:
        action = operation.actions[index]
        definition = get_definition(action.scope, action.object_type)
        if definition is None:
            msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
            raise MistMutationError(msg)
        if not definition.supports_restore_action(action.action):
            msg = f"Unsupported {action.action} for {action.scope}:{action.object_type}"
            raise MistMutationError(msg)

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
                msg = f"Mist did not return an id for created {action.object_type}"
                raise MistMutationError(msg)
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

        await self._record_result(
            operation,
            action,
            definition.sensitive_fields,
            result or payload,
            site_id=site_id,
        )
        action.status = RestoreActionStatus.COMPLETED
        operation.actions[index] = action
        operation.touch()
        await operation.save()

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
        latest = (
            await ObjectVersion.find(ObjectVersion.logical_object_id == logical.id).sort("-version").first_or_none()
        )
        if latest is None:
            msg = "Restore target has no source history"
            raise MistMutationError(msg)

        resulting_id = action.resulting_mist_id or action.current_mist_id
        incarnation = await ObjectIncarnation.get(latest.incarnation_id)
        if action.action is RestoreActionType.CREATE:
            latest_incarnation = (
                await ObjectIncarnation.find(ObjectIncarnation.logical_object_id == logical.id)
                .sort("-ordinal")
                .first_or_none()
            )
            incarnation = ObjectIncarnation(
                organization_id=operation.organization_id,
                logical_object_id=logical.id,
                mist_object_id=resulting_id,
                site_mist_id=site_id,
                ordinal=1 if latest_incarnation is None else latest_incarnation.ordinal + 1,
            )
            await incarnation.insert()
        if incarnation is None or incarnation.id is None:
            msg = "Restore target incarnation is unavailable"
            raise MistMutationError(msg)

        restored_configuration = dict(configuration)
        if action.action is not RestoreActionType.DELETE:
            restored_configuration["id"] = resulting_id
        version = ObjectVersion(
            organization_id=operation.organization_id,
            logical_object_id=logical.id,
            incarnation_id=incarnation.id,
            version=latest.version + 1,
            event=VersionEvent.RESTORED,
            configuration=(
                latest.configuration
                if action.action is RestoreActionType.DELETE
                else protect_configuration(
                    restored_configuration,
                    self._vault,
                    sensitive_fields=sensitive_fields,
                )
            ),
            configuration_hash=(
                latest.configuration_hash
                if action.action is RestoreActionType.DELETE
                else configuration_hash(restored_configuration)
            ),
            changed_fields=[],
            references=(
                latest.references
                if action.action is RestoreActionType.DELETE
                else extract_uuid_references(restored_configuration)
            ),
            is_deleted=action.action is RestoreActionType.DELETE,
            actor=operation.credential_actor,
        )
        await version.insert()
        logical.current_mist_id = resulting_id
        logical.site_mist_id = site_id
        logical.current_version = version.version
        logical.is_deleted = action.action is RestoreActionType.DELETE
        logical.touch()
        await logical.save()

    @staticmethod
    async def _fail_operation(
        operation: RestoreOperation,
        action_index: int,
        message: str,
    ) -> None:
        action = operation.actions[action_index]
        action.status = RestoreActionStatus.FAILED
        action.error = message
        operation.actions[action_index] = action
        operation.failure_action_order = action.order
        operation.status = (
            RestoreStatus.COMPENSATION_AVAILABLE
            if any(item.status is RestoreActionStatus.COMPLETED for item in operation.actions)
            else RestoreStatus.FAILED
        )
        operation.completed_at = utc_now()
        operation.encrypted_delegated_credential = None
        operation.delegated_credential_expires_at = None
        operation.touch()
        await operation.save()


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
