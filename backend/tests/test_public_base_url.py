"""The canonical public origin the application builds activation links from."""

import pytest

from mist_config_guardian_backend.config import Settings


def _settings(**overrides: object) -> Settings:
    # secret_key/credential_encryption_key are rotated away from their "development-only"
    # defaults so that a production-environment test fails (or passes) on the
    # public_base_url validator under test, not on the unrelated startup guard that
    # rejects development secrets in production.
    base: dict[str, object] = {
        "_env_file": None,
        "environment": "development",
        "database_enabled": False,
        "secret_key": "rotated-for-tests-not-a-development-marker",
        "credential_encryption_key": "rotated-for-tests-not-a-development-marker",
    }
    base.update(overrides)
    return Settings(**base)


def test_a_single_cors_origin_is_the_public_base_url() -> None:
    assert _settings(cors_origins="https://guardian.example.com").public_base_url == "https://guardian.example.com"


def test_several_cors_origins_never_pick_a_winner() -> None:
    """CORS is an allow-list, not a declaration of a canonical address."""
    assert _settings(cors_origins="http://localhost:4200,http://localhost:8080").public_base_url is None


def test_no_cors_origin_leaves_the_base_url_unresolved() -> None:
    assert _settings(cors_origins="").public_base_url is None


def test_the_override_wins_over_the_derivation() -> None:
    settings = _settings(
        cors_origins="https://derived.example.com",
        public_base_url_override="https://explicit.example.com",
    )

    assert settings.public_base_url == "https://explicit.example.com"


def test_a_trailing_slash_is_normalised_away() -> None:
    assert _settings(public_base_url_override="https://guardian.example.com/").public_base_url == (
        "https://guardian.example.com"
    )


@pytest.mark.parametrize(
    "value",
    [
        "guardian.example.com",
        "ftp://guardian.example.com",
        "https://user:pass@guardian.example.com",
        "https://guardian.example.com?a=b",
        "https://guardian.example.com#frag",
        "https://",
    ],
)
def test_an_unusable_override_is_a_startup_error(value: str) -> None:
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        _settings(public_base_url_override=value)


def test_production_refuses_a_plaintext_base_url() -> None:
    """The activation POST carries the token and the new password together."""
    with pytest.raises(ValueError, match="https"):
        _settings(environment="production", cors_origins="http://guardian.example.com")


def test_production_accepts_https() -> None:
    settings = _settings(environment="production", cors_origins="https://guardian.example.com")

    assert settings.public_base_url == "https://guardian.example.com"


def test_development_still_accepts_plaintext() -> None:
    assert _settings(cors_origins="http://localhost:4200").public_base_url == "http://localhost:4200"
