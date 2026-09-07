"""Local authentication tests."""

from datetime import UTC, datetime

import pytest
from beanie import PydanticObjectId

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.auth import (
    AccessTokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def _user() -> User:
    return User.model_construct(
        id=PydanticObjectId(),
        email="admin@example.com",
        display_name="Admin",
        password_hash="not-used",
        role=UserRole.ADMINISTRATOR,
    )


def test_password_hash_round_trip() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert password_hash != "correct horse battery staple"
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)


def test_access_token_round_trip() -> None:
    settings = Settings(environment="test", secret_key="unit-test-signing-key-that-is-long-enough")
    user = _user()

    token, expires_in = create_access_token(user, settings)
    claims = decode_access_token(token, settings)

    assert claims.subject == user.id
    assert claims.expires_at > datetime.now(UTC)
    assert expires_in == settings.access_token_expire_minutes * 60


def test_access_token_rejects_wrong_key() -> None:
    token, _ = create_access_token(
        _user(),
        Settings(environment="test", secret_key="first-signing-key-that-is-long-enough"),
    )

    with pytest.raises(AccessTokenError):
        decode_access_token(
            token,
            Settings(environment="test", secret_key="different-signing-key-that-is-long-enough"),
        )
