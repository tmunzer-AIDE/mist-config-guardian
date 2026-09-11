"""SMTP settings persistence and its request schema."""

from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr, ValidationError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.schemas.application_configuration import SmtpSettingsUpdate
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationError,
    ApplicationConfigurationService,
    is_loopback_host,
)


def test_smtp_is_disabled_until_an_administrator_enables_it() -> None:
    configuration = ApplicationConfiguration.model_construct()

    assert configuration.smtp_enabled is False
    assert configuration.smtp_port == 587
    assert configuration.smtp_security == "starttls"
    assert configuration.encrypted_smtp_password is None


def test_the_update_schema_defaults_to_a_disabled_starttls_submission() -> None:
    request = SmtpSettingsUpdate()

    assert request.enabled is False
    assert request.security == "starttls"
    assert request.port == 587
    assert request.clear_password is False


@pytest.mark.parametrize("port", [0, 65536])
def test_a_port_outside_the_usable_range_is_refused(port: int) -> None:
    with pytest.raises(ValidationError):
        SmtpSettingsUpdate(port=port)


def test_an_unknown_security_mode_is_refused() -> None:
    with pytest.raises(ValidationError):
        SmtpSettingsUpdate(security="ssl-maybe")


@pytest.mark.parametrize("host", ["127.0.0.1", "127.1.2.3", "::1"])
def test_a_literal_loopback_address_is_loopback(host: str) -> None:
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["localhost", "mail.internal", "10.0.0.5", "", "::ffff:127.0.0.1"])
def test_anything_needing_resolution_is_not_loopback(host: str) -> None:
    """A name can be rebound between the check and the connection; a literal cannot.

    ``::ffff:127.0.0.1`` is also refused even though the stdlib considers the
    address it embeds a loopback address: it is a second, less obvious
    spelling of ``127.0.0.1`` that the accepted-forms error message does not
    name, so it is rejected rather than silently accepted.
    """
    assert not is_loopback_host(host)


# -- ApplicationConfigurationService.update_smtp / smtp_credentials --------


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> ApplicationConfigurationService:
    """A service over an in-memory configuration with a resolvable base URL.

    A single CORS origin makes ``Settings.public_base_url`` resolvable, so
    tests exercise the SMTP-specific refusals in ``_validate_smtp`` rather
    than being turned away earlier for a reason unrelated to SMTP.
    """
    vault = CredentialVault(
        Settings(
            environment="test",
            database_enabled=False,
            credential_encryption_key=SecretStr("test-encryption-key"),
        )
    )
    settings = Settings(
        environment="test",
        database_enabled=False,
        credential_encryption_key=SecretStr("test-encryption-key"),
        cors_origins="https://app.example.test",
    )
    configuration_service = ApplicationConfigurationService(vault, settings)
    configuration = ApplicationConfiguration.model_construct(key="global")
    monkeypatch.setattr(configuration_service, "_get_or_create", AsyncMock(return_value=configuration))
    monkeypatch.setattr(ApplicationConfiguration, "save", AsyncMock())
    return configuration_service


async def test_enabling_smtp_without_a_host_is_refused(service: ApplicationConfigurationService) -> None:
    with pytest.raises(ApplicationConfigurationError, match="host"):
        await service.update_smtp(SmtpSettingsUpdate(enabled=True, from_address="a@example.com"))


async def test_enabling_smtp_without_a_from_address_is_refused(service: ApplicationConfigurationService) -> None:
    with pytest.raises(ApplicationConfigurationError, match="address"):
        await service.update_smtp(SmtpSettingsUpdate(enabled=True, host="mail.example.com"))


async def test_plaintext_with_a_username_is_refused(service: ApplicationConfigurationService) -> None:
    """An SMTP password in the clear is never the intended configuration."""
    with pytest.raises(ApplicationConfigurationError, match="unencrypted"):
        await service.update_smtp(
            SmtpSettingsUpdate(
                enabled=True,
                host="mail.example.com",
                from_address="a@example.com",
                security="none",
                username="postmaster",
                password="hunter2",
            )
        )


async def test_a_blank_password_leaves_the_stored_one_untouched(service: ApplicationConfigurationService) -> None:
    await service.update_smtp(
        SmtpSettingsUpdate(enabled=True, host="mail.example.com", from_address="a@example.com", password="hunter2")
    )

    response = await service.update_smtp(
        SmtpSettingsUpdate(enabled=True, host="mail.example.com", from_address="a@example.com")
    )

    assert response.password_set
    assert response.password_last_four == "ter2"


async def test_disabled_smtp_has_no_credentials(
    service: ApplicationConfigurationService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``smtp_credentials`` reads the stored document directly rather than through
    ``_get_or_create``, so this stubs the class-level query Beanie normally
    provides once ``init_beanie`` has run, which this test suite never does.
    """
    monkeypatch.setattr(ApplicationConfiguration, "key", "global", raising=False)
    monkeypatch.setattr(ApplicationConfiguration, "find_one", AsyncMock(return_value=None))

    assert await service.smtp_credentials() is None
