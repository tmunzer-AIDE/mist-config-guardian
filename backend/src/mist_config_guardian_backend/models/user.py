"""Local user persistence."""

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal

from beanie import Document, PydanticObjectId
from pydantic import BaseModel, EmailStr, Field
from pymongo import IndexModel

from mist_config_guardian_backend.models.base import TimestampedModel, utc_now


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


async def consume_user_recovery_code(user: User, code_hash: str) -> bool:
    """Spend one recovery code, or report that it was not there to spend.

    The list is edited in the database, not replaced from a copy of it. Writing
    the whole `totp` object back meant two codes redeemed at once each removed
    their own from the same starting list, and the second write put the first
    one back — a single-use code good twice. The same write also undid a
    disable or a regeneration that landed in between, restoring an enrollment
    or a set of codes their owner had just retired.

    The stored digest is matched by the database rather than by
    `hmac.compare_digest`. What that comparison protected against was learning
    a stored hash by timing; the code itself is not recoverable from its
    SHA-256, and it is codes, not hashes, that an attacker can submit.
    """
    now = utc_now()
    result = await User.get_pymongo_collection().update_one(
        {"_id": user.id, "totp.recovery_code_hashes": code_hash},
        {
            "$pull": {"totp.recovery_code_hashes": code_hash},
            "$set": {"updated_at": now},
        },
    )
    if getattr(result, "modified_count", 0) != 1:
        return False
    if user.totp is not None:
        user.totp.recovery_code_hashes = [stored for stored in user.totp.recovery_code_hashes if stored != code_hash]
    user.updated_at = now
    return True


async def write_user_fields(user: User, **fields: object) -> User:
    """Write named fields on a user, touching nothing else.

    A whole-document save carries every value the request loaded, `role`,
    `is_active` and `status` included. A self-service request that read the
    account before an administrator demoted or deactivated it would put the
    old values back when it finished — the account keeping authority, or
    becoming able to sign in again, because its owner changed their display
    name at the right moment. Naming the fields removes the possibility.
    """
    now = utc_now()
    document: dict[str, object] = {"updated_at": now}
    for name, value in fields.items():
        document[name] = value.model_dump(mode="python") if isinstance(value, BaseModel) else value
    await User.get_pymongo_collection().update_one({"_id": user.id}, {"$set": document})
    for name, value in fields.items():
        setattr(user, name, value)
    user.updated_at = now
    return user
