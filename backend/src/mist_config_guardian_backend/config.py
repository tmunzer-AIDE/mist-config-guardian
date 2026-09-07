"""Application configuration."""

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Mist Config Guardian"
    app_version: str = "0.1.0"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    cors_origins: str = "http://localhost:4200,http://localhost:8080"
    secret_key: SecretStr = SecretStr("development-only-change-before-production-64-character-minimum-key")

    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "mist_config_guardian"
    mongodb_connect_timeout_seconds: float = 5.0
    database_enabled: bool = True
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    influxdb_url: str = "http://localhost:8086"
    influxdb_org: str = "mist_config_guardian"
    influxdb_bucket: str = "network_monitoring"
    influxdb_token: SecretStr = SecretStr("")

    access_token_expire_minutes: int = 30
    bootstrap_admin_token: SecretStr = SecretStr("development-only-bootstrap-token")
    credential_encryption_key: SecretStr = SecretStr("development-only-encryption-key")
    webhook_max_body_bytes: int = 1_048_576
    delegated_credential_ttl_minutes: int = 15
    impact_ai_enabled: bool = False
    impact_ai_base_url: str = ""
    impact_ai_model: str = ""
    impact_ai_api_key: SecretStr = SecretStr("")

    @property
    def parsed_cors_origins(self) -> list[str]:
        """Return normalized configured CORS origins."""
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @model_validator(mode="after")
    def reject_development_secret_in_production(self) -> "Settings":
        """Prevent production startup with the development signing secret."""
        if self.environment == "production" and self.secret_key.get_secret_value().startswith("development-only"):
            msg = "SECRET_KEY must be replaced in production"
            raise ValueError(msg)
        if self.environment == "production" and self.credential_encryption_key.get_secret_value().startswith(
            "development-only"
        ):
            msg = "CREDENTIAL_ENCRYPTION_KEY must be replaced in production"
            raise ValueError(msg)
        if self.environment == "production" and self.bootstrap_admin_token.get_secret_value().startswith(
            "development-only"
        ):
            msg = "BOOTSTRAP_ADMIN_TOKEN must be replaced in production"
            raise ValueError(msg)
        if self.impact_ai_enabled and (
            not self.impact_ai_base_url or not self.impact_ai_model or not self.impact_ai_api_key.get_secret_value()
        ):
            msg = "AI impact assessment requires a base URL, model, and API key"
            raise ValueError(msg)
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
