"""Application configuration tests."""

from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr, ValidationError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.application_configuration import (
    ApplicationConfiguration,
)
from mist_config_guardian_backend.schemas.application_configuration import (
    ImpactAiSettingsUpdate,
)
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    ApplicationConfigurationService,
)


def _configuration() -> ApplicationConfiguration:
    return ApplicationConfiguration.model_construct(
        key="global",
        impact_ai_enabled=False,
        impact_ai_base_url="",
        impact_ai_model="",
        encrypted_impact_ai_api_key=None,
        impact_ai_api_key_last_four=None,
    )


def test_enabled_ai_requires_provider_identity() -> None:
    with pytest.raises(ValidationError, match="base URL and model"):
        ImpactAiSettingsUpdate(enabled=True)


async def test_enabled_ai_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ApplicationConfigurationService(
        CredentialVault(
            Settings(
                environment="test",
                database_enabled=False,
                credential_encryption_key=SecretStr("test-encryption-key"),
            )
        )
    )
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=_configuration()))

    with pytest.raises(ApplicationConfigurationError, match="API key is required"):
        await service.update_impact_ai(
            ImpactAiSettingsUpdate(
                enabled=True,
                base_url="https://ai.example.test/v1",
                model="test-model",
            )
        )


async def test_ai_api_key_is_encrypted_and_not_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key=SecretStr("test-encryption-key"),
        )
    )
    service = ApplicationConfigurationService(vault)
    configuration = _configuration()
    monkeypatch.setattr(service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())

    response = await service.update_impact_ai(
        ImpactAiSettingsUpdate(
            enabled=True,
            base_url="https://ai.example.test/v1/",
            model="test-model",
            api_key=SecretStr("provider-secret-key"),
        )
    )

    assert response.api_key_set is True
    assert response.api_key_last_four == "-key"
    assert configuration.encrypted_impact_ai_api_key is not None
    assert "provider-secret-key" not in configuration.encrypted_impact_ai_api_key
    assert (
        vault.decrypt_for_context(
            configuration.encrypted_impact_ai_api_key,
            context="impact-ai-api-key",
        )
        == "provider-secret-key"
    )
