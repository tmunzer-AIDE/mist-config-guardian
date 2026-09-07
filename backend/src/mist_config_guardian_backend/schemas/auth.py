"""Authentication request and response schemas."""

from typing import Literal

from pydantic import BaseModel, EmailStr, Field, SecretStr

from mist_config_guardian_backend.models.user import User, UserRole


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

    @classmethod
    def from_document(cls, user: User) -> "UserResponse":
        """Build a response without exposing the password hash."""
        if user.id is None:
            msg = "Persisted user is missing an identifier"
            raise ValueError(msg)
        return cls(
            id=str(user.id),
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            is_active=user.is_active,
        )
