"""Signed-in account request and response schemas."""

from datetime import datetime
from typing import Any, Literal
from zoneinfo import available_timezones

from pydantic import BaseModel, EmailStr, Field, SecretStr, field_validator

from mist_config_guardian_backend.models.session import UserSession
from mist_config_guardian_backend.models.user import (
    LandingPage,
    User,
    UserPreferences,
    WebAuthnCredential,
)


def _validate_timezone(value: str) -> str:
    if value not in available_timezones():
        msg = f"Unknown time zone: {value}"
        raise ValueError(msg)
    return value


class ProfileResponse(BaseModel):
    """The parts of an account its owner may edit."""

    id: str
    email: EmailStr
    display_name: str
    preferences: UserPreferences
    pending_email: EmailStr | None = None
    pending_email_expires_at: datetime | None = None
    password_changed_at: datetime | None = None

    @classmethod
    def from_document(cls, user: User) -> "ProfileResponse":
        """Build a profile response without exposing confirmation tokens."""
        if user.id is None:
            msg = "Persisted user is missing an identifier"
            raise ValueError(msg)
        pending = user.pending_email_change
        return cls(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            preferences=user.preferences,
            pending_email=pending.new_email if pending else None,
            pending_email_expires_at=pending.expires_at if pending else None,
            password_changed_at=user.password_changed_at,
        )


class ProfileUpdateRequest(BaseModel):
    """Partial update of display name and display preferences."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    clock: Literal["24h", "12h"] | None = None
    landing_page: LandingPage | None = None

    @field_validator("timezone")
    @classmethod
    def check_timezone(cls, value: str | None) -> str | None:
        """Reject time zones the runtime cannot resolve."""
        return None if value is None else _validate_timezone(value)


class EmailChangeRequest(BaseModel):
    """Request to move the account to a new email address."""

    new_email: EmailStr
    password: SecretStr = Field(min_length=1, max_length=1024)


class EmailChangeResponse(BaseModel):
    """A pending email change.

    ``confirmation_token`` is populated only outside production, because this
    deployment has no mail transport to deliver it with.
    """

    pending_email: EmailStr
    expires_at: datetime
    confirmation_token: str | None = None
    delivery: Literal["not_implemented"] = "not_implemented"


class EmailChangeConfirmRequest(BaseModel):
    """Confirmation of a pending email change."""

    token: str = Field(min_length=1, max_length=512)


class PasswordChangeRequest(BaseModel):
    """Password replacement that re-verifies the current password."""

    current_password: SecretStr = Field(min_length=1, max_length=1024)
    new_password: SecretStr = Field(min_length=12, max_length=1024)


class PasswordChangeResponse(BaseModel):
    """Result of a password change, including forced sign-out elsewhere."""

    password_changed_at: datetime
    revoked_sessions: int


class SessionResponse(BaseModel):
    """One live session belonging to the signed-in user."""

    id: str
    label: str
    ip_address: str | None
    location: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    mfa_verified_at: datetime | None
    current: bool

    @classmethod
    def from_document(cls, session: UserSession, *, current: bool) -> "SessionResponse":
        """Build a session response without exposing its token digests."""
        if session.id is None:
            msg = "Persisted session is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(session.id),
            label=session.label,
            ip_address=session.ip_address,
            location=session.location,
            created_at=session.created_at,
            last_seen_at=session.last_seen_at,
            expires_at=session.expires_at,
            mfa_verified_at=session.mfa_verified_at,
            current=current,
        )


class SessionListResponse(BaseModel):
    """Every live session for the signed-in user."""

    items: list[SessionResponse]
    total: int


class SessionRevocationResponse(BaseModel):
    """How many sessions a revocation ended."""

    revoked_sessions: int


class TotpEnrollmentResponse(BaseModel):
    """Unconfirmed enrollment material, shown while setting up an authenticator."""

    secret: str
    otpauth_uri: str
    issuer: str
    qr_svg: str


class TotpConfirmRequest(BaseModel):
    """Authenticator code that confirms a pending enrollment."""

    code: str = Field(min_length=1, max_length=16)


class PasswordConfirmationRequest(BaseModel):
    """Password re-entry that guards a second-factor change."""

    password: SecretStr = Field(min_length=1, max_length=1024)


class RecoveryCodesResponse(BaseModel):
    """Single-use recovery codes, returned exactly once."""

    recovery_codes: list[str]
    generated_at: datetime


class MfaStepUpRequest(BaseModel):
    """An authenticator or recovery code that renews a session's step-up."""

    code: str = Field(min_length=1, max_length=32)


class MfaStepUpResponse(BaseModel):
    """When the renewed step-up stops counting as recent."""

    verified_at: datetime
    expires_at: datetime


class MfaStatusResponse(BaseModel):
    """Whether an authenticator is enrolled and how many codes remain."""

    mfa_enabled: bool
    confirmed_at: datetime | None = None
    recovery_codes_remaining: int = 0


class PasskeyResponse(BaseModel):
    """One registered passkey."""

    id: str
    name: str
    device_kind: Literal["platform", "security_key"]
    transports: list[str]
    backed_up: bool
    created_at: datetime
    last_used_at: datetime | None

    @classmethod
    def from_document(cls, credential: WebAuthnCredential) -> "PasskeyResponse":
        """Build a passkey response without exposing key material."""
        if credential.id is None:
            msg = "Persisted passkey is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(credential.id),
            name=credential.name,
            device_kind=credential.device_kind,
            transports=list(credential.transports),
            backed_up=credential.backed_up,
            created_at=credential.created_at,
            last_used_at=credential.last_used_at,
        )


class PasskeyListResponse(BaseModel):
    """Every passkey registered by the signed-in user."""

    items: list[PasskeyResponse]
    total: int


class PasskeyRegistrationOptionsResponse(BaseModel):
    """WebAuthn options for registering a new passkey."""

    challenge_token: str
    options: dict[str, Any]


class PasskeyRegistrationRequest(BaseModel):
    """The attestation a browser produced while registering a passkey."""

    challenge_token: str = Field(min_length=1, max_length=4096)
    credential: dict[str, Any]
    name: str | None = Field(default=None, min_length=1, max_length=80)


class PasskeyRenameRequest(BaseModel):
    """New display name for a registered passkey."""

    name: str = Field(min_length=1, max_length=80)
