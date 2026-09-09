"""Session cookie configuration, which is only safe if it is enforced."""

import pytest
from pydantic import ValidationError

from mist_config_guardian_backend.config import Settings

PRODUCTION_SECRETS = {
    "secret_key": "x" * 64,
    "credential_encryption_key": "y" * 64,
    "bootstrap_admin_token": "z" * 64,
}


def _production(**overrides: object) -> Settings:
    return Settings(environment="production", **PRODUCTION_SECRETS, **overrides)  # type: ignore[arg-type]


def test_production_secures_the_session_cookie_without_being_asked() -> None:
    """The development default must not follow a deployment into production.

    The cookie is the entire session, so one plaintext request leaks something
    replayable until it expires.
    """
    assert _production().session_cookie_secure is True


def test_production_refuses_to_start_with_the_flag_switched_off() -> None:
    """Silently correcting an explicit choice would hide a deliberate mistake."""
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE cannot be disabled"):
        _production(session_cookie_secure=False)


def test_development_is_left_alone_so_localhost_still_works() -> None:
    """A Secure cookie is dropped over plain HTTP, which is how developers run."""
    assert Settings(environment="development").session_cookie_secure is False
    assert Settings(environment="test").session_cookie_secure is False


def test_cross_site_cookies_must_be_secure_in_any_environment() -> None:
    """Browsers discard SameSite=None without Secure, so this is broken, not lax."""
    with pytest.raises(ValidationError, match="requires SESSION_COOKIE_SECURE"):
        Settings(environment="development", session_cookie_same_site="none")


def test_cross_site_cookies_are_accepted_once_they_are_secure() -> None:
    """The combination browsers actually honour stays configurable."""
    settings = Settings(
        environment="development",
        session_cookie_same_site="none",
        session_cookie_secure=True,
    )

    assert settings.session_cookie_same_site == "none"
