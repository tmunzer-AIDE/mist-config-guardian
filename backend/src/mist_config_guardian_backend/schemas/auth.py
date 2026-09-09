"""Authentication request and response schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, SecretStr

from mist_config_guardian_backend.models.user import (
    User,
    UserPreferences,
    UserRole,
    UserStatus,
)

MfaMethod = Literal["totp", "recovery_code"]


class BootstrapAdminRequest(BaseModel):
    """First local administrator creation request."""

    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    password: SecretStr = Field(min_length=12, max_length=1024)
    bootstrap_token: SecretStr


class AccessTokenResponse(BaseModel):
    """Bearer access token response."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int


class UserResponse(BaseModel):
    """Safe local user representation."""

    id: str
    email: EmailStr
    display_name: str
    role: UserRole
    is_active: bool
    status: UserStatus
    preferences: UserPreferences
    mfa_enabled: bool
    passkey_count: int
    last_login_at: datetime | None = None

    @classmethod
    def from_document(cls, user: User, *, passkey_count: int = 0) -> "UserResponse":
        """Build a response without exposing credential or second-factor material."""
        if user.id is None:
            msg = "Persisted user is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            is_active=user.is_active,
            status=user.status,
            preferences=user.preferences,
            mfa_enabled=user.mfa_enabled,
            passkey_count=passkey_count,
            last_login_at=user.last_login_at,
        )


class LoginSuccessResponse(BaseModel):
    """A completed sign-in, carrying both the session and a bearer token."""

    mfa_required: Literal[False] = False
    user: UserResponse
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int


class MfaChallengeResponse(BaseModel):
    """A password that was accepted but still needs a second factor."""

    mfa_required: Literal[True] = True
    challenge_token: str
    methods: list[MfaMethod]


class MfaLoginRequest(BaseModel):
    """Second-factor submission that completes a pending sign-in."""

    challenge_token: str = Field(min_length=1, max_length=4096)
    code: str = Field(min_length=1, max_length=64)


class PasskeyAuthenticationOptionsResponse(BaseModel):
    """WebAuthn options for a passwordless sign-in attempt."""

    challenge_token: str
    options: dict[str, Any]


class PasskeyAuthenticationRequest(BaseModel):
    """The assertion a browser produced for a passwordless sign-in."""

    challenge_token: str = Field(min_length=1, max_length=4096)
    credential: dict[str, Any]


class AcceptInvitationRequest(BaseModel):
    """Invitation acceptance that sets the account's first password."""

    token: str = Field(min_length=1, max_length=512)
    password: SecretStr = Field(min_length=12, max_length=1024)
    display_name: str | None = Field(default=None, min_length=1, max_length=120)


class LogoutResponse(BaseModel):
    """Result of ending the current session."""

    signed_out: bool = True


class BootstrapStateResponse(BaseModel):
    """Whether the first-administrator form should be offered at all."""

    available: bool
