"""Local user persistence."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, EmailStr, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel


class UserRole(StrEnum):
    """Application authorization role."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMINISTRATOR = "administrator"


class UserStatus(StrEnum):
    """Account lifecycle as presented in user administration."""

    INVITED = "invited"
    ACTIVE = "active"
    DEACTIVATED = "deactivated"


class LandingPage(StrEnum):
    """Page the application opens after sign-in."""

    OVERVIEW = "overview"
    CHANGES = "changes"
    HISTORY = "history"
    RESTORE = "restore"
    IMPACT = "impact"


class UserPreferences(BaseModel):
    """Display preferences applied across the application."""

    timezone: str = "UTC"
    clock: Literal["24h", "12h"] = "24h"
    landing_page: LandingPage = LandingPage.OVERVIEW


class TotpEnrollment(BaseModel):
    """Confirmed time-based one-time-password enrollment."""

    encrypted_secret: str
    confirmed_at: datetime
    recovery_code_hashes: list[str] = Field(default_factory=list)
    recovery_codes_viewed_at: datetime | None = None


class PendingEmailChange(BaseModel):
    """A requested email change awaiting confirmation from the new address."""

    new_email: EmailStr
    token_hash: str
    requested_at: datetime
    expires_at: datetime


class User(TimestampedModel, Document):
    """A local application user."""

    email: EmailStr
    display_name: str
    password_hash: str
    role: UserRole = UserRole.VIEWER
    is_active: bool = True
    status: UserStatus = UserStatus.ACTIVE
    preferences: UserPreferences = Field(default_factory=UserPreferences)
    totp: TotpEnrollment | None = None
    pending_email_change: PendingEmailChange | None = None
    invited_by: PydanticObjectId | None = None
    invitation_token_hash: str | None = None
    invitation_expires_at: datetime | None = None
    password_changed_at: datetime | None = None
    last_login_at: datetime | None = None

    @property
    def mfa_enabled(self) -> bool:
        """Report whether the account completed TOTP enrollment."""
        return self.totp is not None

    class Settings:
        name = "users"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel([("email", 1)], unique=True, name="user_email_unique"),
            IndexModel([("role", 1), ("is_active", 1)]),
        ]


class WebAuthnCredential(TimestampedModel, Document):
    """One registered passkey for a local user."""

    user_id: PydanticObjectId
    credential_id: str
    public_key: str
    sign_count: int = Field(default=0, ge=0)
    name: str
    transports: list[str] = Field(default_factory=list)
    device_kind: Literal["platform", "security_key"] = "platform"
    backed_up: bool = False
    last_used_at: datetime | None = None

    class Settings:
        name = "webauthn_credentials"
        indexes: ClassVar[list[IndexModel]] = [
            IndexModel(
                [("credential_id", 1)],
                unique=True,
                name="webauthn_credential_unique",
            ),
            IndexModel([("user_id", 1), ("created_at", -1)]),
        ]
