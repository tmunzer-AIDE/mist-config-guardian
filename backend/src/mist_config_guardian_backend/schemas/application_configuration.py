"""Administrator-managed application configuration schemas."""

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
