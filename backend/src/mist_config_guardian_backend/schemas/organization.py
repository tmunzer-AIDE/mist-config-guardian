"""Organization request and response schemas."""

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr

from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)


class OrganizationCreateRequest(BaseModel):
    """Onboard a Mist organization with a read-only service token."""

    cloud_region: MistCloudRegion = MistCloudRegion.GLOBAL_01
    service_token: SecretStr = Field(min_length=1, max_length=2048)
    # Introducing a credential the deployment authenticates with, so the caller
    # proves who they are now rather than who signed in earlier.
    password: SecretStr = Field(min_length=1, max_length=1024)
    reconciliation_cron: str = Field(default="0 2 * * *", min_length=1, max_length=120)
    configuration_retention_days: int = Field(default=365, ge=1, le=3650)
    monitoring_retention_days: int = Field(default=90, ge=1, le=3650)


class OrganizationUpdateRequest(BaseModel):
    """Update non-credential organization settings."""

    name: str | None = Field(default=None, min_length=1, max_length=160)
    reconciliation_cron: str | None = Field(default=None, min_length=1, max_length=120)
    configuration_retention_days: int | None = Field(default=None, ge=1, le=3650)
    monitoring_retention_days: int | None = Field(default=None, ge=1, le=3650)


class ServiceTokenUpdateRequest(BaseModel):
    """Replace the organization's read-only service token."""

    service_token: SecretStr = Field(min_length=1, max_length=2048)
    password: SecretStr = Field(min_length=1, max_length=1024)


class WebhookSecretRotateRequest(BaseModel):
    """Rotate the organization's webhook signing secret.

    The new secret is returned once, so this asks for the password the way
    every other credential change does.
    """

    password: SecretStr = Field(min_length=1, max_length=1024)


class OrganizationResponse(BaseModel):
    """Safe organization representation."""

    id: str
    mist_org_id: str
    name: str
    cloud_region: MistCloudRegion
    status: OrganizationStatus
    service_token_set: bool
    service_token_last_four: str
    credential_verified_at: datetime | None
    credential_error: str | None
    discovered_privileges: list[str]
    webhook_secret_set: bool
    webhook_secret_last_four: str | None
    webhook_secret_rotated_at: datetime | None
    webhook_last_received_at: datetime | None
    webhook_last_signature_valid: bool | None
    initial_snapshot_completed_at: datetime | None
    reconciliation_cron: str
    configuration_retention_days: int
    monitoring_retention_days: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_document(cls, organization: Organization) -> "OrganizationResponse":
        """Build a response without exposing encrypted credential material."""
        if organization.id is None:
            msg = "Persisted organization is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(organization.id),
            mist_org_id=organization.mist_org_id,
            name=organization.name,
            cloud_region=organization.cloud_region,
            status=organization.status,
            service_token_set=bool(organization.encrypted_service_token),
            service_token_last_four=organization.service_token_last_four,
            credential_verified_at=organization.credential_verified_at,
            credential_error=organization.credential_error,
            discovered_privileges=list(organization.discovered_privileges),
            webhook_secret_set=bool(organization.encrypted_webhook_secret),
            webhook_secret_last_four=organization.webhook_secret_last_four,
            webhook_secret_rotated_at=organization.webhook_secret_rotated_at,
            webhook_last_received_at=organization.webhook_last_received_at,
            webhook_last_signature_valid=organization.webhook_last_signature_valid,
            initial_snapshot_completed_at=organization.initial_snapshot_completed_at,
            reconciliation_cron=organization.reconciliation_cron,
            configuration_retention_days=organization.configuration_retention_days,
            monitoring_retention_days=organization.monitoring_retention_days,
            created_at=organization.created_at,
            updated_at=organization.updated_at,
        )


class OrganizationListResponse(BaseModel):
    """Paginated organization list."""

    items: list[OrganizationResponse]
    total: int


class WebhookSecretResponse(BaseModel):
    """One-time webhook secret and organization-bound endpoint."""

    endpoint: str
    secret: str
