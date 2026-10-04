"""Administrator application configuration API tests."""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
from beanie import PydanticObjectId
from pydantic import SecretStr

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    require_administrator,
)
from mist_config_guardian_backend.api.routes.ai import get_ai_audit_recorder
from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.guardian.agent_schema import ACTION_SCHEMA_VERSION, capability_fingerprint
from mist_config_guardian_backend.integrations.ai_provider import TEXT, AiCompletion, JsonSchemaFormat
from mist_config_guardian_backend.main import create_app
from mist_config_guardian_backend.models.application_configuration import (
    ApplicationConfiguration,
    StructuredOutputCapability,
)
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.schemas.application_configuration import (
    ImpactAiSettingsResponse,
    ImpactAiSettingsUpdate,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import ApplicationConfigurationService


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


# --- structured-output capability in the AI settings response ----------------


BASE_URL = "https://ai.example.test/v1"


def _stored_configuration(**overrides) -> ApplicationConfiguration:
    values = {
        "key": "global",
        "impact_ai_enabled": True,
        "impact_ai_base_url": BASE_URL,
        "impact_ai_model": "test-model",
        "encrypted_impact_ai_api_key": "v1:ciphertext",
        "impact_ai_api_key_last_four": "-key",
        "impact_ai_max_response_tokens": 1500,
        "impact_ai_automatic_summaries": False,
        "impact_ai_last_test_at": None,
        "impact_ai_last_test_ok": None,
        "impact_ai_last_test_detail": None,
        "impact_ai_structured_output": StructuredOutputCapability(
            mode="json_schema",
            fingerprint=capability_fingerprint(base_url=BASE_URL, model="test-model"),
            schema_version=ACTION_SCHEMA_VERSION,
            tested_at=datetime(2026, 9, 16, 9, 30, tzinfo=UTC),
        ),
    }
    return ApplicationConfiguration.model_construct(**(values | overrides))


async def _ai_settings(configuration: ApplicationConfiguration, monkeypatch: pytest.MonkeyPatch) -> httpx.Response:
    settings = Settings(environment="test", database_enabled=False)
    service = ApplicationConfigurationService(
        CredentialVault(
            Settings(
                environment="test",
                database_enabled=False,
                credential_encryption_key=SecretStr("test-encryption-key"),
            )
        ),
        settings,
    )
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    app = create_app(settings)
    app.dependency_overrides[get_application_configuration_service] = lambda: service
    app.dependency_overrides[require_administrator] = _administrator
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        return await client.get("/api/v1/ai/settings")


async def test_ai_settings_expose_the_capability_without_any_key_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = await _ai_settings(_stored_configuration(), monkeypatch)

    assert response.status_code == 200
    payload = response.json()
    assert payload["structured_output"] == {
        "mode": "json_schema",
        "matches_fingerprint": True,
        "tested_at": "2026-09-16T09:30:00Z",
    }
    stored = capability_fingerprint(base_url=BASE_URL, model="test-model")
    assert stored not in json.dumps(payload)
    assert "ciphertext" not in response.text
    assert payload["api_key_set"] is True


async def test_a_record_for_another_model_is_reported_as_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    response = await _ai_settings(_stored_configuration(impact_ai_model="new-model"), monkeypatch)

    assert response.json()["structured_output"]["matches_fingerprint"] is False


async def test_settings_without_a_probe_expose_no_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    response = await _ai_settings(_stored_configuration(impact_ai_structured_output=None), monkeypatch)

    assert response.json()["structured_output"] is None


# --- the settings page's "Test connection" ----------------------------------


class _ProbeAnsweringProvider:
    """Answers the connection check and the structured-output probe, without a network."""

    def __init__(self) -> None:
        self.formats: list[object] = []

    async def complete(self, messages, *, max_tokens=None, response_format=TEXT) -> AiCompletion:  # noqa: ARG002 - mirrors the provider protocol
        self.formats.append(response_format)
        return AiCompletion(content=_PROBE_REPORT, model="test-model")

    async def list_models(self):
        return []

    async def test_connection(self) -> tuple[bool, str]:
        return True, "Connected to test-model."

    async def aclose(self) -> None:
        return None


class _NoAudit:
    async def record(self, record: object) -> None:  # noqa: ARG002 - mirrors the audit sink protocol
        return None


_PROBE_REPORT = json.dumps(
    {
        "action": "report",
        "peak_impact": "none",
        "current_impact": "none",
        "confidence": "low",
        "summary": "capability probe",
        "evidence": [],
    }
)


async def test_the_settings_page_test_body_probes_and_records_the_saved_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ai-tab.ts always sends ``{base_url, model}``; for the saved, unedited provider that must still probe it."""
    configuration = _stored_configuration(encrypted_impact_ai_api_key=None, impact_ai_structured_output=None)
    provider = _ProbeAnsweringProvider()
    settings = Settings(environment="test", database_enabled=False)
    service = ApplicationConfigurationService(
        CredentialVault(settings), settings, provider_factory=lambda **_kwargs: provider
    )
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "get_pymongo_collection", AsyncMock)
    app = create_app(settings)
    app.dependency_overrides[get_application_configuration_service] = lambda: service
    app.dependency_overrides[require_administrator] = _administrator
    app.dependency_overrides[get_ai_audit_recorder] = _NoAudit

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/ai/settings/test", json={"base_url": BASE_URL, "model": "test-model"})

    assert response.status_code == 200
    assert any(isinstance(requested, JsonSchemaFormat) for requested in provider.formats)
    assert configuration.impact_ai_structured_output is not None
    assert configuration.impact_ai_last_test_ok is True
