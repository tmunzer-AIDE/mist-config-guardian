"""SMTP settings persistence and its request schema."""

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.models.application_configuration import ApplicationConfiguration
from mist_config_guardian_backend.schemas.application_configuration import SmtpSettingsUpdate


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
