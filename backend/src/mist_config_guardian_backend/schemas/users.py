"""User administration request and response schemas."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from mist_config_guardian_backend.models.user import User, UserRole, UserStatus


class UserSummaryResponse(BaseModel):
    """Safe administrative view of one local user."""

    id: str
    email: EmailStr
    display_name: str
    role: UserRole
    status: UserStatus
    is_active: bool
    mfa_enabled: bool
    invitation_expires_at: datetime | None
    last_login_at: datetime | None
    created_at: datetime

    @classmethod
    def from_document(cls, user: User) -> "UserSummaryResponse":
        """Build a summary without exposing password or invitation digests."""
        if user.id is None:
            msg = "Persisted user is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            status=user.status,
            is_active=user.is_active,
            mfa_enabled=user.mfa_enabled,
            invitation_expires_at=user.invitation_expires_at,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
        )


class UserListResponse(BaseModel):
    """A page of local users."""

    items: list[UserSummaryResponse]
    total: int


class UserInviteRequest(BaseModel):
    """Invite a new local user without setting a password for them."""

    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    role: UserRole = UserRole.VIEWER


class UserInviteResponse(BaseModel):
    """A created invitation and what became of it.

    ``invitation_token`` and ``invitation_url`` are populated unless positive
    SMTP acceptance was observed. "Email did not carry it" is not observable —
    a server can queue a message while the client times out before reading the
    reply — so the rule is one-directional and errs towards giving the
    administrator something to pass on.
    """

    user: UserSummaryResponse
    invitation_expires_at: datetime | None
    delivery: Literal["sent", "uncertain", "not_configured", "failed"]
    invitation_token: str | None = None
    invitation_url: str | None = None
    delivery_detail: str | None = None


class UserUpdateRequest(BaseModel):
    """Partial update of a user's display name and role."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: UserRole | None = None
