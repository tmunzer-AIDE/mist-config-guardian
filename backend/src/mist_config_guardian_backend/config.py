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
    app_version: str = "0.6.2"
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
    # Deliberately empty. A default that works is a credential published in
    # the repository: the first caller to reach a fresh deployment and send it
    # becomes the global administrator. Bootstrap stays closed until an
    # operator sets a value of their own.
    bootstrap_admin_token: SecretStr = SecretStr("")
    credential_encryption_key: SecretStr = SecretStr("development-only-encryption-key")
    webhook_max_body_bytes: int = 1_048_576
    delegated_credential_ttl_minutes: int = 15

    session_cookie_name: str = "cg_session"
    csrf_cookie_name: str = "cg_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    session_absolute_lifetime_days: int = 30
    session_idle_timeout_minutes: int = 720
    session_cookie_secure: bool = False
    session_cookie_domain: str | None = None
    session_cookie_same_site: Literal["lax", "strict", "none"] = "lax"

    totp_issuer: str = "Mist Config Guardian"
    mfa_step_up_window_minutes: int = 10
    # A sign-in challenge dies after this many wrong codes, whatever its lifetime.
    mfa_challenge_max_attempts: int = 5
    # Failed sign-ins and password confirmations are counted per account and per
    # client address inside a fixed window; reaching a limit answers 429 until
    # the window ends.
    sign_in_throttle_window_minutes: int = 15
    sign_in_failures_per_account: int = 10
    sign_in_failures_per_address: int = 100

    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Mist Config Guardian"
    webauthn_origin: str = "http://localhost:4200"

    ai_request_timeout_seconds: float = 45.0
    ai_max_response_tokens: int = 1500

    notification_retention_days: int = 90

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
        return self

    @model_validator(mode="after")
    def require_secure_session_cookies(self) -> "Settings":
        """Keep the session cookie off plaintext requests.

        The cookie is the whole session: sent once over HTTP it is readable by
        anything on the path and replayable until it expires. Production
        therefore defaults to ``Secure`` rather than inheriting the development
        default, and refuses to start when it is switched off explicitly.

        ``SameSite=None`` is rejected everywhere without it, because browsers
        discard such a cookie outright: the deployment would not be insecure so
        much as broken, in a way that only shows up in a browser.
        """
        if self.environment == "production" and not self.session_cookie_secure:
            if "session_cookie_secure" in self.model_fields_set:
                msg = "SESSION_COOKIE_SECURE cannot be disabled in production"
                raise ValueError(msg)
            self.session_cookie_secure = True
        if self.session_cookie_same_site == "none" and not self.session_cookie_secure:
            msg = "SESSION_COOKIE_SAME_SITE='none' requires SESSION_COOKIE_SECURE"
            raise ValueError(msg)
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings instance."""
    return Settings()
