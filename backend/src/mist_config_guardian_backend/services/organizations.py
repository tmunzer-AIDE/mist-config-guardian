"""Mist organization onboarding and settings."""

import secrets

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.integrations.mist import MistVerificationError, MistVerificationService
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.organization import Organization, OrganizationStatus
from mist_config_guardian_backend.schemas.organization import (
    OrganizationCreateRequest,
    OrganizationUpdateRequest,
)
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError, CredentialVault
from mist_config_guardian_backend.services.service_credentials import service_token


class OrganizationNotFoundError(ValueError):
    """Raised when an organization does not exist."""


class OrganizationAlreadyExistsError(ValueError):
    """Raised when a Mist organization is already managed."""


async def _write_fields(
    organization: Organization, criteria: dict[str, object] | None = None, **fields: object
) -> None:
    """Write the named fields and ``updated_at`` with a targeted ``$set``, then mirror them onto ``organization``.

    Never ``organization.save()``: Beanie writes the whole document, so an
    instance read before a call to Mist - up to thirty seconds - would carry
    its stale copy of every other field back over a change completed in the
    meantime, such as a webhook-secret rotation or a token replacement. See
    webhooks.py for the same hazard. ``criteria`` narrows the write to a
    document that still says what this request read.
    """
    now = utc_now()
    document: dict[str, object] = {**fields, "updated_at": now}
    await Organization.get_pymongo_collection().update_one(
        {"_id": organization.id, **(criteria or {})},
        {"$set": document},
    )
    for name, value in document.items():
        setattr(organization, name, value)


class OrganizationService:
    """Manage organization onboarding and credentials."""

    def __init__(self, vault: CredentialVault, mist: MistVerificationService) -> None:
        self._vault = vault
        self._mist = mist

    async def create(self, request: OrganizationCreateRequest) -> Organization:
        """Verify and persist a new organization."""
        token = request.service_token.get_secret_value()
        access = await self._mist.verify_read_only_token(
            token=token,
            region=request.cloud_region,
        )
        now = utc_now()
        organization = Organization(
            mist_org_id=access.org_id,
            name=access.org_name,
            cloud_region=request.cloud_region,
            status=OrganizationStatus.VERIFIED,
            encrypted_service_token=self._vault.encrypt(token),
            service_token_last_four=token[-4:].rjust(4, "*"),
            credential_verified_at=now,
            discovered_privileges=list(access.privileges),
            reconciliation_cron=request.reconciliation_cron,
            configuration_retention_days=request.configuration_retention_days,
            monitoring_retention_days=request.monitoring_retention_days,
        )
        try:
            await organization.insert()
        except DuplicateKeyError as exc:
            msg = "This Mist organization is already managed"
            raise OrganizationAlreadyExistsError(msg) from exc
        return organization

    async def list(self, *, skip: int, limit: int) -> tuple[list[Organization], int]:
        """List managed organizations."""
        query = Organization.find_all()
        total = await query.count()
        organizations = await query.sort("name").skip(skip).limit(limit).to_list()
        return organizations, total

    async def get(self, organization_id: PydanticObjectId) -> Organization:
        """Get a managed organization."""
        organization = await Organization.get(organization_id)
        if organization is None:
            msg = "Organization not found"
            raise OrganizationNotFoundError(msg)
        return organization

    async def update(
        self,
        organization_id: PydanticObjectId,
        request: OrganizationUpdateRequest,
    ) -> Organization:
        """Update organization settings."""
        organization = await self.get(organization_id)
        updates = request.model_dump(exclude_none=True)
        await _write_fields(
            organization,
            **{field_name: value.strip() if isinstance(value, str) else value for field_name, value in updates.items()},
        )
        return organization

    async def replace_service_token(
        self,
        organization_id: PydanticObjectId,
        token: str,
    ) -> Organization:
        """Verify and replace a stored read-only service token."""
        organization = await self.get(organization_id)
        access = await self._mist.verify_read_only_token(
            token=token,
            region=organization.cloud_region,
        )
        self._ensure_same_org(
            access.org_id,
            organization.mist_org_id,
            "The replacement token belongs to a different organization",
        )
        await _write_fields(
            organization,
            encrypted_service_token=self._vault.encrypt(token),
            service_token_last_four=token[-4:].rjust(4, "*"),
            credential_verified_at=utc_now(),
            credential_error=None,
            discovered_privileges=list(access.privileges),
            status=OrganizationStatus.VERIFIED,
        )
        return organization

    async def verify_stored_token(self, organization_id: PydanticObjectId) -> Organization:
        """Verify the stored token and persist current health."""
        organization = await self.get(organization_id)
        try:
            access = await self._mist.verify_read_only_token(
                token=await self._stored_token(organization),
                region=organization.cloud_region,
            )
            self._ensure_same_org(
                access.org_id,
                organization.mist_org_id,
                "The stored token belongs to a different organization",
            )
        except MistVerificationError as exc:
            await self._record_health(organization, status=OrganizationStatus.ERROR, credential_error=str(exc))
            raise

        await self._record_health(
            organization,
            status=OrganizationStatus.VERIFIED,
            credential_verified_at=utc_now(),
            credential_error=None,
            discovered_privileges=list(access.privileges),
        )
        return organization

    async def _stored_token(self, organization: Organization) -> str:
        """Decrypt the stored token, failing as a verification when it cannot be."""
        try:
            return await service_token(organization, self._vault)
        except CredentialDecryptionError as exc:
            # Corrupted, or encrypted under a key that has since rotated: the
            # organization cannot reach Mist until the token is replaced.
            msg = "The stored service token could not be decrypted; replace it"
            raise MistVerificationError(msg) from exc

    @staticmethod
    async def _record_health(organization: Organization, **fields: object) -> None:
        # Only while the stored token is still the one verified: a replacement
        # saved during the call to Mist has its own, newer verdict.
        await _write_fields(organization, {"encrypted_service_token": organization.encrypted_service_token}, **fields)

    @staticmethod
    def _ensure_same_org(actual_org_id: str, expected_org_id: str, message: str) -> None:
        if actual_org_id != expected_org_id:
            raise MistVerificationError(message)

    async def rotate_webhook_secret(
        self,
        organization_id: PydanticObjectId,
    ) -> tuple[Organization, str]:
        """Generate and persist a new webhook signature secret."""
        organization = await self.get(organization_id)
        webhook_secret = secrets.token_urlsafe(32)
        await _write_fields(
            organization,
            encrypted_webhook_secret=self._vault.encrypt_for_context(
                webhook_secret,
                context=f"webhook-signature:{organization.mist_org_id}",
            ),
            webhook_secret_last_four=webhook_secret[-4:],
            webhook_secret_rotated_at=utc_now(),
        )
        return organization, webhook_secret
