"""Mist organization persistence."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from beanie import Document
from pydantic import Field, field_validator
from pymongo import IndexModel

from mist_config_guardian_backend.models.approval import ApprovalPolicy
from mist_config_guardian_backend.models.base import TimestampedModel


class OrganizationStatus(StrEnum):
    """Organization onboarding state."""

    PENDING = "pending"
    VERIFIED = "verified"
    ERROR = "error"
    DISABLED = "disabled"


class MistCloudRegion(StrEnum):
    """Supported Mist API cloud regions."""

    GLOBAL_01 = "global_01"
    GLOBAL_02 = "global_02"
    GLOBAL_03 = "global_03"
    GLOBAL_04 = "global_04"
    GLOBAL_05 = "global_05"
    EMEA_01 = "emea_01"
    EMEA_02 = "emea_02"
    EMEA_03 = "emea_03"
    EMEA_04 = "emea_04"
    APAC_01 = "apac_01"
    APAC_02 = "apac_02"
    APAC_03 = "apac_03"


class Organization(TimestampedModel, Document):
    """A managed Mist organization and its encrypted read-only credential."""

    mist_org_id: str
    name: str
    cloud_region: MistCloudRegion = MistCloudRegion.GLOBAL_01
    status: OrganizationStatus = OrganizationStatus.PENDING

    encrypted_service_token: str
    service_token_last_four: str = Field(min_length=4, max_length=4)
    credential_key_version: int = Field(default=1, ge=1)
    credential_verified_at: datetime | None = None
    credential_error: str | None = None
    discovered_privileges: list[str] = Field(default_factory=list)

    encrypted_webhook_secret: str | None = None
    webhook_secret_last_four: str | None = Field(default=None, min_length=4, max_length=4)
    webhook_secret_rotated_at: datetime | None = None
    webhook_last_received_at: datetime | None = None
    webhook_last_signature_valid: bool | None = None

    initial_snapshot_completed_at: datetime | None = None
    reconciliation_cron: str = "0 2 * * *"
    configuration_retention_days: int = Field(default=365, ge=1)
    monitoring_retention_days: int = Field(default=90, ge=1)
    approval_policy: ApprovalPolicy = Field(default_factory=ApprovalPolicy)

    @field_validator("cloud_region", mode="before")
    @classmethod
    def migrate_legacy_cloud_region(cls, value: object) -> object:
        """Load region values written before Mist's cloud list was expanded."""
        return {"global": "global_01", "europe": "emea_01"}.get(value, value)

    class Settings:
        name = "organizations"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("mist_org_id", 1)], unique=True, name="organization_mist_id_unique"),
            IndexModel([("status", 1)]),
            IndexModel([("name", 1)]),
        ]
