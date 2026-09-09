"""Administrator-managed application configuration schemas."""

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr, model_validator


class ImpactAiSettingsUpdate(BaseModel):
    """Update the optional AI impact provider."""

    enabled: bool = False
    base_url: str = Field(default="", max_length=2048)
    model: str = Field(default="", max_length=255)
    api_key: SecretStr | None = Field(default=None, min_length=1, max_length=4096)
    clear_api_key: bool = False

    @model_validator(mode="after")
    def validate_provider(self) -> "ImpactAiSettingsUpdate":
        """Require provider identity when AI assessment is enabled."""
        self.base_url = self.base_url.strip().rstrip("/")
        self.model = self.model.strip()
        if self.enabled and (not self.base_url or not self.model):
            msg = "AI base URL and model are required when AI assessment is enabled"
            raise ValueError(msg)
        if self.base_url and not self.base_url.startswith(("http://", "https://")):
            msg = "AI base URL must use HTTP or HTTPS"
            raise ValueError(msg)
        if self.api_key is not None and self.clear_api_key:
            msg = "An API key cannot be replaced and cleared in the same request"
            raise ValueError(msg)
        return self


class ImpactAiSettingsResponse(BaseModel):
    """Safe AI provider settings without encrypted credential material."""

    enabled: bool
    base_url: str
    model: str
    api_key_set: bool
    api_key_last_four: str | None


class AiSettingsUpdate(BaseModel):
    """Update the optional AI provider used for assistance and assessment."""

    enabled: bool = False
    base_url: str = Field(default="", max_length=2048)
    model: str = Field(default="", max_length=255)
    api_key: SecretStr | None = Field(default=None, max_length=4096)
    clear_api_key: bool = False
    max_response_tokens: int = Field(default=1500, ge=256, le=32_000)
    automatic_summaries: bool = False
    # These settings hold a provider API key, so changing them is a credential
    # change and is confirmed like one.
    password: SecretStr = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def validate_provider(self) -> "AiSettingsUpdate":
        """Normalise the provider identity and reject contradictory key edits."""
        self.base_url = self.base_url.strip().rstrip("/")
        self.model = self.model.strip()
        if self.api_key is not None and not self.api_key.get_secret_value().strip():
            self.api_key = None
        if self.enabled and (not self.base_url or not self.model):
            msg = "AI base URL and model are required when AI assistance is enabled"
            raise ValueError(msg)
        if self.base_url and not self.base_url.startswith(("http://", "https://")):
            msg = "AI base URL must use HTTP or HTTPS"
            raise ValueError(msg)
        if self.api_key is not None and self.clear_api_key:
            msg = "An API key cannot be replaced and cleared in the same request"
            raise ValueError(msg)
        return self


class AiProviderDraft(BaseModel):
    """Probe unsaved provider settings without changing the active provider."""

    base_url: str = Field(max_length=2048)
    model: str = Field(default="", max_length=255)
    api_key: SecretStr | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def validate_provider(self) -> "AiProviderDraft":
        """Normalise the endpoint and allow discovery before model selection."""
        self.base_url = self.base_url.strip().rstrip("/")
        self.model = self.model.strip()
        if not self.base_url.startswith(("http://", "https://")):
            msg = "AI base URL must use HTTP or HTTPS"
            raise ValueError(msg)
        if self.api_key is not None and not self.api_key.get_secret_value().strip():
            self.api_key = None
        return self


class AiSettingsResponse(BaseModel):
    """Safe AI provider settings without encrypted credential material."""

    enabled: bool
    base_url: str
    model: str
    api_key_set: bool
    api_key_last_four: str | None
    max_response_tokens: int
    automatic_summaries: bool
    last_test_at: datetime | None = None
    last_test_ok: bool | None = None
    last_test_detail: str | None = None


class AiConnectionTestResponse(BaseModel):
    """Result of a provider credential and model health check."""

    ok: bool
    detail: str
    checked_at: datetime


class AiModelResponse(BaseModel):
    """One model advertised by the configured provider."""

    id: str
    owned_by: str | None = None
    context_window: int | None = None


class AiModelListResponse(BaseModel):
    """Models discovered from the configured provider."""

    items: list[AiModelResponse]
