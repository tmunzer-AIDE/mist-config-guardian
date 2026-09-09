"""Fresh Mist administrator authorization for restore execution."""

from datetime import timedelta

from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.snapshots.registry import get_definition
from mist_config_guardian_backend.snapshots.secrets import reveal_configuration


class RestoreAuthorizationError(ValueError):
    """Raised when a restore cannot be authorized."""


class RestoreAuthorizationService:
    """Verify and temporarily hold a delegated Mist credential."""

    def __init__(
        self,
        settings: Settings,
        vault: CredentialVault,
        mist: MistVerificationService,
    ) -> None:
        self._settings = settings
        self._vault = vault
        self._mist = mist

    async def authorize(
        self,
        organization_id: PydanticObjectId,
        operation_id: PydanticObjectId,
        credential: str,
        task_id: str,
    ) -> RestoreOperation:
        """Verify a write identity and atomically reserve the plan."""
        organization = await Organization.get(organization_id)
        operation = await RestoreOperation.find_one(
            RestoreOperation.id == operation_id,
            RestoreOperation.organization_id == organization_id,
        )
        if organization is None or operation is None:
            msg = "Restore operation not found"
            raise RestoreAuthorizationError(msg)
        if operation.status is not RestoreStatus.PLANNED:
            msg = "Restore operation is not awaiting execution"
            raise RestoreAuthorizationError(msg)
        if operation.preflight_errors:
            msg = "Restore plan has unresolved preflight errors"
            raise RestoreAuthorizationError(msg)
        if operation.id is None:
            msg = "Persisted restore operation is missing an identifier"
            raise RestoreAuthorizationError(msg)

        self._validate_action_secrets(operation)

        access = await self._mist.verify_write_token(
            token=credential,
            org_id=organization.mist_org_id,
            region=organization.cloud_region,
        )
        expires_at = utc_now() + timedelta(minutes=self._settings.delegated_credential_ttl_minutes)
        encrypted = self._vault.encrypt_for_context(
            credential,
            context=f"restore:{operation.id}",
        )
        result = await RestoreOperation.find_one(
            RestoreOperation.id == operation.id,
            RestoreOperation.status == RestoreStatus.PLANNED,
        ).update(
            {
                "$set": {
                    "status": RestoreStatus.QUEUED,
                    "credential_actor": access.actor,
                    "encrypted_delegated_credential": encrypted,
                    "delegated_credential_expires_at": expires_at,
                    "task_id": task_id,
                    "updated_at": utc_now(),
                }
            }
        )
        if result is None or result.modified_count != 1:
            msg = "Restore operation was authorized by another request"
            raise RestoreAuthorizationError(msg)
        refreshed = await RestoreOperation.get(operation.id)
        if refreshed is None:
            msg = "Authorized restore operation could not be reloaded"
            raise RestoreAuthorizationError(msg)
        return refreshed

    def _validate_action_secrets(self, operation: RestoreOperation) -> None:
        for action in operation.actions:
            if action.action == "delete":
                continue
            definition = get_definition(action.scope, action.object_type)
            if definition is None:
                msg = f"Unsupported restore type: {action.scope}:{action.object_type}"
                raise RestoreAuthorizationError(msg)
            configuration = reveal_configuration(
                action.protected_configuration,
                self._vault,
            )
            missing = find_unavailable_secrets(
                configuration,
                definition.sensitive_fields,
            )
            if missing:
                fields = ", ".join(sorted(format_secret_path(path) for path in missing))
                msg = f"{action.object_name} requires unavailable secret values: {fields}"
                raise RestoreAuthorizationError(msg)

    @staticmethod
    async def release(operation_id: PydanticObjectId, task_id: str) -> None:
        """Return a plan to review when task delivery fails."""
        await RestoreOperation.find_one(
            RestoreOperation.id == operation_id,
            RestoreOperation.status == RestoreStatus.QUEUED,
            RestoreOperation.task_id == task_id,
        ).update(
            {
                "$set": {
                    "status": RestoreStatus.PLANNED,
                    "encrypted_delegated_credential": None,
                    "delegated_credential_expires_at": None,
                    "task_id": None,
                    "updated_at": utc_now(),
                }
            }
        )

    @staticmethod
    async def expire_stale_credentials() -> int:
        """Fail queued restores whose delegated credential expired."""
        result = await RestoreOperation.find(
            RestoreOperation.status == RestoreStatus.QUEUED,
            {"delegated_credential_expires_at": {"$lte": utc_now()}},
        ).update_many(
            {
                "$set": {
                    "status": RestoreStatus.FAILED,
                    "encrypted_delegated_credential": None,
                    "delegated_credential_expires_at": None,
                    "completed_at": utc_now(),
                    "updated_at": utc_now(),
                },
                "$push": {"preflight_errors": ("Delegated Mist administrator credential expired before execution")},
            }
        )
        return result.modified_count


# One step into a configuration: a mapping key, or a position in a sequence.
SecretPath = tuple[str | int, ...]


def format_secret_path(path: SecretPath) -> str:
    """Render a location for a person to read. Never for comparing two."""
    return ".".join(str(step) for step in path)


def find_unavailable_secrets(
    value: object,
    sensitive_fields: frozenset[str],
    *,
    path: SecretPath = (),
) -> set[SecretPath]:
    """Find explicitly masked secrets that cannot be replayed safely.

    Each location is reported as the steps taken to reach it rather than as a
    dotted string. A configuration is an arbitrary document: a key may itself
    contain a dot, and a mapping key may look like a list index, so joining the
    steps gives two different locations the same name. Anything deciding
    whether two locations are the same has to compare the steps.
    """
    missing: set[SecretPath] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            if str(key).lower() in sensitive_fields and (
                child is None or child == "" or (isinstance(child, str) and set(child) == {"*"})
            ):
                missing.add(child_path)
            else:
                missing.update(
                    find_unavailable_secrets(
                        child,
                        sensitive_fields,
                        path=child_path,
                    )
                )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            missing.update(
                find_unavailable_secrets(
                    child,
                    sensitive_fields,
                    path=(*path, index),
                )
            )
    return missing
