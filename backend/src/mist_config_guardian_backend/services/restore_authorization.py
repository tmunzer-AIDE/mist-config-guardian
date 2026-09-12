"""Fresh Mist administrator authorization for restore execution."""

from datetime import timedelta
from typing import Any

import httpx
import structlog
from beanie import PydanticObjectId
from pymongo import ReturnDocument

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.integrations.mist import REGION_HOSTS, MistVerificationService
from mist_config_guardian_backend.integrations.mist_session import SESSION_PREFIX, credential_headers, logout_session
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.restore import RestoreOperation, RestoreStatus
from mist_config_guardian_backend.schemas.mist_login import MistLoginCredentials
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.restore_planner import unavailable_secret_errors
from mist_config_guardian_backend.services.throttling import get_throttle_service, reserve_or_raise

logger = structlog.get_logger(__name__)


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
        credential: str | MistLoginCredentials,
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

        if isinstance(credential, MistLoginCredentials):
            throttle = get_throttle_service(self._settings)
            account = throttle.account(str(credential.email))
            await reserve_or_raise(throttle, account)
            credential, _identity = await self._mist.login(credential, organization.cloud_region, retain_session=True)
            await throttle.succeeded(account)

        retained = False
        try:
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
            retained = True
            return refreshed
        finally:
            if not retained and credential.startswith(SESSION_PREFIX):
                async with httpx.AsyncClient(
                    base_url=REGION_HOSTS[organization.cloud_region],
                    headers=credential_headers(credential),
                    timeout=10,
                ) as client:
                    await logout_session(client)

    def _validate_action_secrets(self, operation: RestoreOperation) -> None:
        """Refuse a plan whose secrets Mist never returned.

        Planning names these in ``preflight_errors`` so a reviewer sees them
        first. This is the same rule applied again at the last moment, because
        a plan can be authorized long after it was built and the check is what
        stands between a mask and a live credential.
        """
        errors = unavailable_secret_errors(operation.actions, self._vault)
        if errors:
            raise RestoreAuthorizationError(errors[0])

    async def release(self, operation_id: PydanticObjectId, task_id: str) -> None:
        """Release only this queued task and revoke its unused Mist session.

        Atomically take the old credential while clearing it. A separate read
        could log out a running task or discard a newly authorized credential.
        The captured secret stays in memory only until logout is attempted.
        """
        operation = await RestoreOperation.get_pymongo_collection().find_one_and_update(
            {"_id": operation_id, "status": RestoreStatus.QUEUED, "task_id": task_id},
            {
                "$set": {
                    "status": RestoreStatus.PLANNED,
                    "encrypted_delegated_credential": None,
                    "delegated_credential_expires_at": None,
                    "task_id": None,
                    "updated_at": utc_now(),
                }
            },
            return_document=ReturnDocument.BEFORE,
            projection={"encrypted_delegated_credential": 1, "organization_id": 1},
        )
        if operation is not None:
            await self._logout_unused_credential(operation)

    async def expire_stale_credentials(self) -> int:
        """Fail expired queued restores and revoke each captured Mist session."""
        now = utc_now()
        count = 0
        collection = RestoreOperation.get_pymongo_collection()
        while operation := await collection.find_one_and_update(
            {"status": RestoreStatus.QUEUED, "delegated_credential_expires_at": {"$lte": now}},
            {
                "$set": {
                    "status": RestoreStatus.FAILED,
                    "encrypted_delegated_credential": None,
                    "delegated_credential_expires_at": None,
                    "completed_at": now,
                    "updated_at": now,
                },
                "$push": {"preflight_errors": "Delegated Mist administrator credential expired before execution"},
            },
            return_document=ReturnDocument.BEFORE,
            projection={"encrypted_delegated_credential": 1, "organization_id": 1},
        ):
            count += 1
            await self._logout_unused_credential(operation)
        return count

    async def _logout_unused_credential(self, operation: dict[str, Any]) -> None:
        """Best-effort logout must not prevent local expiry or queue recovery."""
        encrypted = operation.get("encrypted_delegated_credential")
        if not encrypted:
            return
        try:
            credential = self._vault.decrypt_for_context(encrypted, context=f"restore:{operation['_id']}")
            if not credential.startswith(SESSION_PREFIX):
                return
            organization = await Organization.get(operation["organization_id"])
            if organization is None:
                logger.warning("restore_session_logout_organization_missing", operation_id=str(operation["_id"]))
                return
            async with httpx.AsyncClient(
                base_url=REGION_HOSTS[organization.cloud_region],
                headers=credential_headers(credential),
                timeout=10,
            ) as client:
                await logout_session(client)
        except (ValueError, KeyError, TypeError):
            # Do not log the exception: malformed credential data may be in it.
            logger.warning("restore_session_logout_credential_invalid", operation_id=str(operation.get("_id")))
