"""Organization response safety tests."""

from beanie import PydanticObjectId

from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.schemas.organization import OrganizationResponse


def test_organization_response_never_exposes_encrypted_token() -> None:
    organization = Organization.model_construct(
        id=PydanticObjectId(),
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-secret",
        service_token_last_four="1234",
        credential_key_version=1,
        credential_verified_at=None,
        credential_error=None,
        discovered_privileges=["read", "org"],
        initial_snapshot_completed_at=None,
        reconciliation_cron="0 2 * * *",
        configuration_retention_days=365,
        monitoring_retention_days=90,
    )

    payload = OrganizationResponse.from_document(organization).model_dump()

    assert payload["service_token_set"] is True
    assert payload["service_token_last_four"] == "1234"
    assert "encrypted_service_token" not in payload


def test_organization_loads_legacy_cloud_region() -> None:
    normalized = Organization.migrate_legacy_cloud_region("global")

    assert normalized == MistCloudRegion.GLOBAL_01
