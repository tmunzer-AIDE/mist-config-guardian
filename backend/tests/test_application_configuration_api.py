"""Administrator application configuration API tests."""

import httpx
from beanie import PydanticObjectId

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    require_administrator,
)
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.schemas.application_configuration import (
    ImpactAiSettingsResponse,
    ImpactAiSettingsUpdate,
)


def _administrator() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="admin@example.com",
        display_name="Admin",
        password_hash="unused",
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )


class _FakeApplicationConfigurationService:
    received: ImpactAiSettingsUpdate | None = None

    async def get_impact_ai(self) -> ImpactAiSettingsResponse:
        return ImpactAiSettingsResponse(
            enabled=False,
            base_url="",
            model="",
            api_key_set=False,
            api_key_last_four=None,
        )

    async def update_impact_ai(
        self,
        request: ImpactAiSettingsUpdate,
    ) -> ImpactAiSettingsResponse:
        self.received = request
        return ImpactAiSettingsResponse(
            enabled=request.enabled,
            base_url=request.base_url,
            model=request.model,
            api_key_set=request.api_key is not None,
            api_key_last_four="-key",
        )


async def test_update_impact_ai_never_returns_api_key() -> None:
    app = create_app(Settings(environment="test", database_enabled=False))
    service = _FakeApplicationConfigurationService()
    app.dependency_overrides[get_application_configuration_service] = lambda: service
    app.dependency_overrides[require_administrator] = _administrator

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.put(
            "/api/v1/settings/impact-ai",
            json={
                "enabled": True,
                "base_url": "https://ai.example.test/v1",
                "model": "test-model",
                "api_key": "provider-secret-key",
                "clear_api_key": False,
            },
        )

    assert response.status_code == 200
    assert service.received is not None
    assert service.received.api_key is not None
    assert service.received.api_key.get_secret_value() == "provider-secret-key"
    assert response.json()["api_key_set"] is True
    assert "provider-secret-key" not in response.text
