"""Application-wide configuration management."""

from dataclasses import dataclass

from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.models.application_configuration import (
    ApplicationConfiguration,
)
from mist_config_guardian_backend.schemas.application_configuration import (
    ImpactAiSettingsResponse,
    ImpactAiSettingsUpdate,
)
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)

_IMPACT_AI_KEY_CONTEXT = "impact-ai-api-key"


class ApplicationConfigurationError(ValueError):
    """Raised when persisted application configuration is unusable."""


@dataclass(frozen=True)
class ImpactAiRuntimeConfiguration:
    """Decrypted provider configuration used only by the monitoring worker."""

    base_url: str
    model: str
    api_key: str


class ApplicationConfigurationService:
    """Read and update global settings with encrypted credentials."""

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    async def get_impact_ai(self) -> ImpactAiSettingsResponse:
        """Return safe AI provider settings."""
        configuration = await self._get_or_create()
        return self._response(configuration)

    async def update_impact_ai(
        self,
        request: ImpactAiSettingsUpdate,
    ) -> ImpactAiSettingsResponse:
        """Persist AI provider settings and optionally replace its API key."""
        configuration = await self._get_or_create()
        api_key = request.api_key.get_secret_value() if request.api_key is not None else None
        if api_key is not None:
            configuration.encrypted_impact_ai_api_key = self._vault.encrypt_for_context(
                api_key,
                context=_IMPACT_AI_KEY_CONTEXT,
            )
            configuration.impact_ai_api_key_last_four = api_key[-4:].rjust(4, "*")
        elif request.clear_api_key:
            configuration.encrypted_impact_ai_api_key = None
            configuration.impact_ai_api_key_last_four = None

        if request.enabled and configuration.encrypted_impact_ai_api_key is None:
            msg = "An AI provider API key is required before AI assessment can be enabled"
            raise ApplicationConfigurationError(msg)

        configuration.impact_ai_enabled = request.enabled
        configuration.impact_ai_base_url = request.base_url
        configuration.impact_ai_model = request.model
        configuration.touch()
        await configuration.save()
        return self._response(configuration)

    async def impact_ai_runtime(self) -> ImpactAiRuntimeConfiguration | None:
        """Return decrypted provider settings when AI assessment is enabled."""
        configuration = await ApplicationConfiguration.find_one(ApplicationConfiguration.key == "global")
        if configuration is None or not configuration.impact_ai_enabled:
            return None
        if not configuration.impact_ai_base_url or not configuration.impact_ai_model:
            msg = "AI impact assessment is enabled without a base URL or model"
            raise ApplicationConfigurationError(msg)
        if not configuration.encrypted_impact_ai_api_key:
            msg = "AI impact assessment is enabled without an API key"
            raise ApplicationConfigurationError(msg)
        try:
            api_key = self._vault.decrypt_for_context(
                configuration.encrypted_impact_ai_api_key,
                context=_IMPACT_AI_KEY_CONTEXT,
            )
        except CredentialDecryptionError as exc:
            msg = "The stored AI provider API key could not be decrypted"
            raise ApplicationConfigurationError(msg) from exc
        return ImpactAiRuntimeConfiguration(
            base_url=configuration.impact_ai_base_url,
            model=configuration.impact_ai_model,
            api_key=api_key,
        )

    @staticmethod
    def _response(
        configuration: ApplicationConfiguration,
    ) -> ImpactAiSettingsResponse:
        return ImpactAiSettingsResponse(
            enabled=configuration.impact_ai_enabled,
            base_url=configuration.impact_ai_base_url,
            model=configuration.impact_ai_model,
            api_key_set=configuration.encrypted_impact_ai_api_key is not None,
            api_key_last_four=configuration.impact_ai_api_key_last_four,
        )

    @staticmethod
    async def _get_or_create() -> ApplicationConfiguration:
        configuration = await ApplicationConfiguration.find_one(ApplicationConfiguration.key == "global")
        if configuration is not None:
            return configuration
        configuration = ApplicationConfiguration()
        try:
            await configuration.insert()
        except DuplicateKeyError:
            existing = await ApplicationConfiguration.find_one(ApplicationConfiguration.key == "global")
            if existing is None:
                raise
            return existing
        else:
            return configuration
