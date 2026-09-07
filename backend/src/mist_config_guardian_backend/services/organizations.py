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
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.service_credentials import service_token


class OrganizationNotFoundError(ValueError):
    """Raised when an organization does not exist."""


class OrganizationAlreadyExistsError(ValueError):
    """Raised when a Mist organization is already managed."""


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
        for field_name, value in updates.items():
            setattr(organization, field_name, value.strip() if isinstance(value, str) else value)
        organization.touch()
        await organization.save()
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
        organization.encrypted_service_token = self._vault.encrypt(token)
        organization.service_token_last_four = token[-4:].rjust(4, "*")
        organization.credential_verified_at = utc_now()
        organization.credential_error = None
        organization.discovered_privileges = list(access.privileges)
        organization.status = OrganizationStatus.VERIFIED
        organization.touch()
        await organization.save()
        return organization

    async def verify_stored_token(self, organization_id: PydanticObjectId) -> Organization:
        """Verify the stored token and persist current health."""
        organization = await self.get(organization_id)
        token = await service_token(organization, self._vault)
        try:
            access = await self._mist.verify_read_only_token(
                token=token,
                region=organization.cloud_region,
            )
            self._ensure_same_org(
                access.org_id,
                organization.mist_org_id,
                "The stored token belongs to a different organization",
            )
        except MistVerificationError as exc:
            organization.status = OrganizationStatus.ERROR
            organization.credential_error = str(exc)
            organization.touch()
            await organization.save()
            raise

        organization.status = OrganizationStatus.VERIFIED
        organization.credential_verified_at = utc_now()
        organization.credential_error = None
        organization.discovered_privileges = list(access.privileges)
        organization.touch()
        await organization.save()
        return organization

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
        organization.encrypted_webhook_secret = self._vault.encrypt_for_context(
            webhook_secret,
            context=f"webhook-signature:{organization.mist_org_id}",
        )
        organization.webhook_secret_last_four = webhook_secret[-4:]
        organization.webhook_secret_rotated_at = utc_now()
        organization.touch()
        await organization.save()
        return organization, webhook_secret
