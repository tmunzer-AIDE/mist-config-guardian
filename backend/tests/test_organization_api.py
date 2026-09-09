"""Organization API tests."""

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import get_organization_service, require_administrator
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.organization import (
    MistCloudRegion,
    Organization,
    OrganizationStatus,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.schemas.organization import OrganizationCreateRequest
from mist_config_guardian_backend.security.auth import hash_password

ADMIN_PASSWORD = "a-long-enough-password"


def _administrator() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="admin@example.com",
        display_name="Admin",
        password_hash=hash_password(ADMIN_PASSWORD),
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )


def _organization() -> Organization:
    return Organization.model_construct(
        id=PydanticObjectId(),
        mist_org_id="org-1",
        name="Lab",
        cloud_region=MistCloudRegion.GLOBAL_01,
        status=OrganizationStatus.VERIFIED,
        encrypted_service_token="v1:encrypted-value",
        service_token_last_four="alue",
        credential_key_version=1,
        credential_verified_at=None,
        credential_error=None,
        discovered_privileges=["read", "org"],
        initial_snapshot_completed_at=None,
        reconciliation_cron="0 2 * * *",
        configuration_retention_days=365,
        monitoring_retention_days=90,
    )


class _FakeOrganizationService:
    received_token: str | None = None

    async def create(self, request: OrganizationCreateRequest) -> Organization:
        self.received_token = request.service_token.get_secret_value()
        return _organization()

    async def list(self, *, skip: int, limit: int) -> tuple[list[Organization], int]:
        assert skip == 0
        assert limit == 50
        return [_organization()], 1


async def test_create_organization_never_returns_token() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))
    service = _FakeOrganizationService()
    app.dependency_overrides[get_organization_service] = lambda: service
    app.dependency_overrides[require_administrator] = _administrator

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/organizations",
            json={
                "cloud_region": "global_01",
                "service_token": "read-only-token-value",
            },
        )

    assert response.status_code == 201
    assert service.received_token == "read-only-token-value"
    assert response.json()["service_token_last_four"] == "alue"
    assert "encrypted_service_token" not in response.text
    assert "read-only-token-value" not in response.text


async def test_list_organizations_requires_authentication() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/organizations")

    assert response.status_code == 401


async def test_operator_cannot_save_admin_settings_without_a_password():
    from mist_config_guardian_backend.api.dependencies import get_current_user  # noqa: PLC0415

    app = create_app(Settings(environment="test", database_enabled=False))
    operator = _administrator()
    operator.role = UserRole.OPERATOR
    app.dependency_overrides[get_current_user] = lambda: operator
    org_id = str(PydanticObjectId())
    paths = [
        ("POST", "/api/v1/organizations", {"cloud_region": "global_01", "service_token": "read-only-token"}),
        ("PUT", f"/api/v1/organizations/{org_id}/service-token", {"service_token": "read-only-token"}),
        ("POST", f"/api/v1/organizations/{org_id}/webhook-secret/rotate", {}),
        ("PUT", "/api/v1/ai/settings", {"enabled": False}),
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        for method, path, body in paths:
            response = await client.request(method, path, json=body)
            assert response.status_code == 403, (path, response.text)
