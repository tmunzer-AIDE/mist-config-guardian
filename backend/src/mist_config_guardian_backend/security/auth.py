"""Local password and access-token security."""

from datetime import UTC, datetime, timedelta

import jwt
from beanie import PydanticObjectId
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.user import User

_ISSUER = "mist-config-guardian"
_ALGORITHM = "HS256"
_PASSWORD_HASH = PasswordHash.recommended()


class AccessTokenClaims(BaseModel):
    """Validated access-token claims."""

    subject: PydanticObjectId
    expires_at: datetime


class AccessTokenError(ValueError):
    """Raised when an access token is invalid."""


def hash_password(password: str) -> str:
    """Hash a local account password with Argon2."""
    return _PASSWORD_HASH.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a local account password."""
    return _PASSWORD_HASH.verify(password, password_hash)


def create_access_token(user: User, settings: Settings) -> tuple[str, int]:
    """Create a short-lived signed access token."""
    if user.id is None:
        msg = "Cannot issue a token for an unpersisted user"
        raise ValueError(msg)
    lifetime = timedelta(minutes=settings.access_token_expire_minutes)
    expires_at = datetime.now(UTC) + lifetime
    encoded = jwt.encode(
        {
            "sub": str(user.id),
            "iss": _ISSUER,
            "aud": _ISSUER,
            "iat": datetime.now(UTC),
            "exp": expires_at,
        },
        settings.secret_key.get_secret_value(),
        algorithm=_ALGORITHM,
    )
    return encoded, int(lifetime.total_seconds())


def decode_access_token(token: str, settings: Settings) -> AccessTokenClaims:
    """Validate and decode an access token."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[_ALGORITHM],
            audience=_ISSUER,
            issuer=_ISSUER,
        )
        subject = PydanticObjectId(payload["sub"])
        expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)
    except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
        msg = "Invalid or expired access token"
        raise AccessTokenError(msg) from exc
    return AccessTokenClaims(subject=subject, expires_at=expires_at)
