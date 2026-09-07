"""User administration request and response schemas."""

from datetime import datetime

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
    """A created invitation.

    ``invitation_token`` is populated only outside production, because this
    deployment has no mail transport to deliver it with.
    """

    user: UserSummaryResponse
    invitation_expires_at: datetime | None
    invitation_token: str | None = None
    delivery: str = "not_implemented"


class UserUpdateRequest(BaseModel):
    """Partial update of a user's display name and role."""

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: UserRole | None = None
