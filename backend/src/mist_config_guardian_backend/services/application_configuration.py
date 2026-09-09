"""Application-wide configuration management."""

import time
from dataclasses import dataclass
from typing import Literal, Protocol

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.ai_provider import (
    AiProvider,
    AiProviderError,
    OpenAiCompatibleProvider,
)
from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.schemas.application_configuration import (
    AiConnectionTestResponse,
    AiModelResponse,
    AiProviderDraft,
    AiSettingsResponse,
    AiSettingsUpdate,
    ImpactAiSettingsResponse,
    ImpactAiSettingsUpdate,
)
from mist_config_guardian_backend.security.credentials import (
    CredentialDecryptionError,
    CredentialVault,
)

_IMPACT_AI_KEY_CONTEXT = "impact-ai-api-key"
_AI_PROVIDER_KEY_CONTEXT = "ai-provider-key"


class ApplicationConfigurationError(ValueError):
    """Raised when persisted application configuration is unusable."""


@dataclass(frozen=True)
class ImpactAiRuntimeConfiguration:
    """Decrypted provider configuration used only by the monitoring worker."""

    base_url: str
    model: str
    api_key: str


@dataclass(frozen=True)
class AiRuntimeConfiguration:
    """Decrypted provider configuration used by every AI-backed feature."""

    base_url: str
    model: str
    api_key: str
    max_response_tokens: int
    automatic_summaries: bool


AiPurpose = Literal["impact_assessment", "diff_summary", "diff_followup", "connection_test"]


@dataclass(frozen=True)
class AiRequestRecord:
    """Bounded metadata describing one outbound provider call.

    Prompt text is deliberately absent: only what is needed to audit that a
    request happened, what it covered, and whether it succeeded.
    """

    purpose: AiPurpose
    base_url: str
    model: str
    duration_ms: int
    succeeded: bool
    organization_id: PydanticObjectId | None = None
    user_id: PydanticObjectId | None = None
    subject_id: str | None = None
    request_tokens: int | None = None
    response_tokens: int | None = None
    error: str | None = None
    redaction_applied: bool = True


class AiAuditSink(Protocol):
    """Sink that persists one outbound provider call record."""

    async def record(self, record: AiRequestRecord) -> None:
        """Persist an audit record."""
        ...


class AiProviderFactory(Protocol):
    """Build a provider client, so tests can substitute a fake."""

    def __call__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        timeout: float,
        max_response_tokens: int,
    ) -> AiProvider:
        """Return a provider client bound to the supplied credentials."""
        ...


def build_openai_compatible_provider(
    *,
    base_url: str,
    model: str,
    api_key: str,
    timeout: float,
    max_response_tokens: int,
) -> AiProvider:
    """Build the default OpenAI-compatible provider client."""
    return OpenAiCompatibleProvider(
        base_url=base_url,
        model=model,
        api_key=api_key,
        timeout=timeout,
        max_response_tokens=max_response_tokens,
    )


class ApplicationConfigurationService:
    """Read and update global settings with encrypted credentials."""

    def __init__(
        self,
        vault: CredentialVault,
        settings: Settings | None = None,
        provider_factory: AiProviderFactory | None = None,
    ) -> None:
        self._vault = vault
        self._settings = settings or get_settings()
        self._provider_factory: AiProviderFactory = provider_factory or build_openai_compatible_provider

    # -- impact assessment settings (existing surface) ---------------------
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
        runtime = await self.ai_runtime()
        if runtime is None:
            return None
        return ImpactAiRuntimeConfiguration(
            base_url=runtime.base_url,
            model=runtime.model,
            api_key=runtime.api_key,
        )

    # -- generalised AI settings ------------------------------------------
    async def get_ai_settings(self) -> AiSettingsResponse:
        """Return safe AI provider settings including assistance options."""
        configuration = await self._get_or_create()
        return self._ai_response(configuration)

    async def update_ai_settings(self, request: AiSettingsUpdate) -> AiSettingsResponse:
        """Persist AI provider settings, leaving a blank API key untouched."""
        configuration = await self._get_or_create()
        api_key = request.api_key.get_secret_value() if request.api_key is not None else None
        if api_key:
            configuration.encrypted_impact_ai_api_key = self._vault.encrypt_for_context(
                api_key,
                context=_AI_PROVIDER_KEY_CONTEXT,
            )
            configuration.impact_ai_api_key_last_four = api_key[-4:].rjust(4, "*")
        elif request.clear_api_key:
            configuration.encrypted_impact_ai_api_key = None
            configuration.impact_ai_api_key_last_four = None

        configuration.impact_ai_enabled = request.enabled
        configuration.impact_ai_base_url = request.base_url
        configuration.impact_ai_model = request.model
        configuration.impact_ai_max_response_tokens = request.max_response_tokens
        configuration.impact_ai_automatic_summaries = request.automatic_summaries
        configuration.touch()
        await configuration.save()
        return self._ai_response(configuration)

    async def ai_runtime(self) -> AiRuntimeConfiguration | None:
        """Return decrypted provider settings when AI assistance is enabled."""
        configuration = await ApplicationConfiguration.find_one(ApplicationConfiguration.key == "global")
        if configuration is None or not configuration.impact_ai_enabled:
            return None
        return self._runtime(configuration)

    async def test_ai_connection(
        self, recorder: AiAuditSink | None = None, *, draft: AiProviderDraft | None = None
    ) -> AiConnectionTestResponse:
        """Probe a draft, or check the stored provider and persist its outcome."""
        configuration = await self._get_or_create()
        runtime = self._draft_runtime(configuration, draft) if draft else self._runtime(configuration)
        provider = self._build_provider(runtime)
        started = time.perf_counter()
        try:
            if runtime.model:
                ok, detail = await provider.test_connection()
            else:
                await provider.list_models()
                ok, detail = True, "Connected. Select a model, then test again to verify completions."
        except AiProviderError as exc:
            ok, detail = False, str(exc)
        finally:
            await provider.aclose()
        duration_ms = int((time.perf_counter() - started) * 1000)
        checked_at = utc_now()
        if draft is None:
            configuration.impact_ai_last_test_at = checked_at
            configuration.impact_ai_last_test_ok = ok
            configuration.impact_ai_last_test_detail = detail
            configuration.touch()
            await configuration.save()
        if recorder is not None:
            await recorder.record(
                AiRequestRecord(
                    purpose="connection_test",
                    base_url=runtime.base_url,
                    model=runtime.model,
                    duration_ms=duration_ms,
                    succeeded=ok,
                    error=None if ok else detail,
                )
            )
        return AiConnectionTestResponse(ok=ok, detail=detail, checked_at=checked_at)

    async def list_ai_models(self, *, draft: AiProviderDraft | None = None) -> list[AiModelResponse]:
        """Discover models using the draft when supplied, otherwise saved settings."""
        configuration = await self._get_or_create()
        runtime = (
            self._draft_runtime(configuration, draft) if draft else self._runtime(configuration, require_model=False)
        )
        provider = self._build_provider(runtime)
        try:
            models = await provider.list_models()
        finally:
            await provider.aclose()
        return [
            AiModelResponse(
                id=model.id,
                owned_by=model.owned_by,
                context_window=model.context_window,
            )
            for model in models
        ]

    # -- internals ---------------------------------------------------------
    def _draft_runtime(self, configuration: ApplicationConfiguration, draft: AiProviderDraft) -> AiRuntimeConfiguration:
        # A draft URL must never redirect a saved credential to another server.
        # Reusing it at a new endpoint still requires the authenticated save flow.
        api_key = ""
        if draft.api_key is not None:
            api_key = draft.api_key.get_secret_value()
        elif draft.base_url == configuration.impact_ai_base_url.rstrip("/"):
            api_key = self._decrypt_api_key(configuration)
        return AiRuntimeConfiguration(
            base_url=draft.base_url,
            model=draft.model,
            api_key=api_key,
            max_response_tokens=configuration.impact_ai_max_response_tokens,
            automatic_summaries=False,
        )

    def _build_provider(self, runtime: AiRuntimeConfiguration) -> AiProvider:
        return self._provider_factory(
            base_url=runtime.base_url,
            model=runtime.model,
            api_key=runtime.api_key,
            timeout=self._settings.ai_request_timeout_seconds,
            max_response_tokens=runtime.max_response_tokens,
        )

    def _runtime(
        self,
        configuration: ApplicationConfiguration,
        *,
        require_model: bool = True,
    ) -> AiRuntimeConfiguration:
        if not configuration.impact_ai_base_url:
            msg = "The AI provider base URL has not been configured"
            raise ApplicationConfigurationError(msg)
        if require_model and not configuration.impact_ai_model:
            msg = "The AI provider model has not been configured"
            raise ApplicationConfigurationError(msg)
        return AiRuntimeConfiguration(
            base_url=configuration.impact_ai_base_url,
            model=configuration.impact_ai_model,
            api_key=self._decrypt_api_key(configuration),
            max_response_tokens=configuration.impact_ai_max_response_tokens or self._settings.ai_max_response_tokens,
            automatic_summaries=configuration.impact_ai_automatic_summaries,
        )

    def _decrypt_api_key(self, configuration: ApplicationConfiguration) -> str:
        encrypted = configuration.encrypted_impact_ai_api_key
        if not encrypted:
            return ""
        for context in (_AI_PROVIDER_KEY_CONTEXT, _IMPACT_AI_KEY_CONTEXT):
            try:
                return self._vault.decrypt_for_context(encrypted, context=context)
            except CredentialDecryptionError:
                continue
        msg = "The stored AI provider API key could not be decrypted"
        raise ApplicationConfigurationError(msg)

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
    def _ai_response(configuration: ApplicationConfiguration) -> AiSettingsResponse:
        return AiSettingsResponse(
            enabled=configuration.impact_ai_enabled,
            base_url=configuration.impact_ai_base_url,
            model=configuration.impact_ai_model,
            api_key_set=configuration.encrypted_impact_ai_api_key is not None,
            api_key_last_four=configuration.impact_ai_api_key_last_four,
            max_response_tokens=configuration.impact_ai_max_response_tokens,
            automatic_summaries=configuration.impact_ai_automatic_summaries,
            last_test_at=configuration.impact_ai_last_test_at,
            last_test_ok=configuration.impact_ai_last_test_ok,
            last_test_detail=configuration.impact_ai_last_test_detail,
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
