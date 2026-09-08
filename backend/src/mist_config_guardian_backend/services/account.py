"""Self-service profile, email, and password management for the signed-in user."""

import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.user import PendingEmailChange, User, UserPreferences, write_user_fields
from mist_config_guardian_backend.schemas.account import ProfileUpdateRequest
from mist_config_guardian_backend.security.auth import hash_password, verify_password
from mist_config_guardian_backend.services.users import (
    InvalidPasswordError,
    UserAlreadyExistsError,
    hash_opaque_token,
)

EMAIL_CHANGE_LIFETIME_HOURS = 24
_EMAIL_TOKEN_BYTES = 32


class EmailChangeError(ValueError):
    """Raised when an email change cannot be requested, confirmed, or cancelled."""


class AccountService:
    """Apply the changes a user is allowed to make to their own account."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def update_profile(self, user: User, request: ProfileUpdateRequest) -> User:
        """Apply display name and display preference changes."""
        if request.display_name is not None and request.display_name.strip():
            user.display_name = request.display_name.strip()
        preferences = user.preferences or UserPreferences()
        user.preferences = UserPreferences(
            timezone=request.timezone if request.timezone is not None else preferences.timezone,
            clock=request.clock if request.clock is not None else preferences.clock,
            landing_page=(request.landing_page if request.landing_page is not None else preferences.landing_page),
        )
        await write_user_fields(user, display_name=user.display_name, preferences=user.preferences)
        return user

    async def request_email_change(
        self,
        user: User,
        *,
        new_email: str,
        password: str,
    ) -> tuple[User, str]:
        """Record a pending email change and return its one-time confirmation token.

        Delivery is not implemented: this deployment has no mail transport, so
        the caller is responsible for getting the token to the new address.
        """
        self._require_password(user, password)
        normalized = new_email.lower().strip()
        if hmac.compare_digest(normalized, str(user.email).lower()):
            msg = "That is already your email address"
            raise EmailChangeError(msg)
        if await User.find_one({"email": normalized}) is not None:
            msg = "A user with this email already exists"
            raise UserAlreadyExistsError(msg)

        token = secrets.token_urlsafe(_EMAIL_TOKEN_BYTES)
        now = utc_now()
        user.pending_email_change = PendingEmailChange(
            new_email=normalized,
            token_hash=hash_opaque_token(token),
            requested_at=now,
            expires_at=now + timedelta(hours=EMAIL_CHANGE_LIFETIME_HOURS),
        )
        await write_user_fields(user, pending_email_change=user.pending_email_change)
        return user, token

    async def confirm_email_change(self, user: User, token: str) -> User:
        """Apply a pending email change once its token is confirmed."""
        pending = user.pending_email_change
        invalid = "This confirmation link is invalid or has expired"
        if pending is None:
            raise EmailChangeError(invalid)
        if not hmac.compare_digest(pending.token_hash, hash_opaque_token(token)):
            raise EmailChangeError(invalid)
        if _expired(pending.expires_at):
            raise EmailChangeError(invalid)
        if await User.find_one({"email": str(pending.new_email).lower()}) is not None:
            msg = "A user with this email already exists"
            raise UserAlreadyExistsError(msg)

        await write_user_fields(user, email=pending.new_email, pending_email_change=None)
        return user

    async def cancel_email_change(self, user: User) -> User:
        """Withdraw a pending email change."""
        if user.pending_email_change is None:
            msg = "No email change is pending"
            raise EmailChangeError(msg)
        await write_user_fields(user, pending_email_change=None)
        return user

    async def change_password(self, user: User, *, current_password: str, new_password: str) -> User:
        """Replace an account password after re-entering the current one."""
        self._require_password(user, current_password)
        await write_user_fields(
            user,
            password_hash=hash_password(new_password),
            password_changed_at=utc_now(),
        )
        return user

    @staticmethod
    def _require_password(user: User, password: str) -> None:
        if not verify_password(password, user.password_hash):
            msg = "The password you entered is incorrect"
            raise InvalidPasswordError(msg)


def get_account_service(settings: Annotated[Settings, Depends(get_settings)]) -> AccountService:
    """Build the signed-in account self-service."""
    return AccountService(settings)


def _expired(value: datetime) -> bool:
    """Report whether a stored expiry, possibly naive from MongoDB, has passed."""
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment <= utc_now()
