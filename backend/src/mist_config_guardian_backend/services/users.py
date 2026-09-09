"""Local user lifecycle service."""

import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.base import utc_now
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus, write_user_fields
from mist_config_guardian_backend.schemas.auth import BootstrapAdminRequest
from mist_config_guardian_backend.security.auth import hash_password, verify_password

INVITATION_LIFETIME_DAYS = 7
_INVITATION_TOKEN_BYTES = 32


class BootstrapClosedError(ValueError):
    """Raised when first-admin bootstrap has already completed."""


class InvalidBootstrapTokenError(ValueError):
    """Raised when the bootstrap secret is invalid."""


class UserAlreadyExistsError(ValueError):
    """Raised when a local user email already exists."""


class UserNotFoundError(ValueError):
    """Raised when a local user cannot be resolved."""


class InvalidPasswordError(ValueError):
    """Raised when a re-entered account password does not match."""


class InvitationError(ValueError):
    """Raised when an invitation token is unusable."""


class LastAdministratorError(ValueError):
    """Raised when a change would leave the deployment without an administrator."""


def hash_opaque_token(token: str) -> str:
    """Hash a high-entropy, server-generated token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


@cache
def _decoy_password_hash() -> str:
    """Return a hash used to equalize timing for unknown email addresses."""
    return hash_password(secrets.token_urlsafe(32))


class UserService:
    """Manage local users and credential verification."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def bootstrap_available(self) -> bool:
        """Report whether the first administrator can still be created.

        This is the read behind the sign-in page's choice of form, and it
        answers exactly what ``bootstrap_administrator`` would enforce: an
        account already exists, or no token is configured, and either way the
        route cannot be used.
        """
        if await User.count() > 0:
            return False
        return bool(self._settings.bootstrap_admin_token.get_secret_value())

    async def bootstrap_administrator(self, request: BootstrapAdminRequest) -> User:
        """Create the first local administrator exactly once."""
        if await User.count() > 0:
            msg = "Administrator bootstrap is already complete"
            raise BootstrapClosedError(msg)

        expected = self._settings.bootstrap_admin_token.get_secret_value()
        if not expected:
            # No token configured, so there is no correct answer and the route
            # cannot be used. Refused as closed rather than as a wrong guess:
            # an unconfigured deployment is not one attempt away from handing
            # out its first administrator.
            msg = "Administrator bootstrap is disabled until BOOTSTRAP_ADMIN_TOKEN is configured"
            raise BootstrapClosedError(msg)
        supplied = request.bootstrap_token.get_secret_value()
        if not secrets.compare_digest(supplied, expected):
            msg = "Invalid bootstrap token"
            raise InvalidBootstrapTokenError(msg)

        user = User(
            email=str(request.email).lower(),
            display_name=request.display_name.strip(),
            password_hash=hash_password(request.password.get_secret_value()),
            role=UserRole.ADMINISTRATOR,
        )
        try:
            await user.insert()
        except DuplicateKeyError as exc:
            msg = "A user with this email already exists"
            raise UserAlreadyExistsError(msg) from exc
        return user

    async def authenticate(self, email: str, password: str) -> User | None:
        """Authenticate an active local user.

        Unknown addresses still pay the cost of one password verification so
        that response timing does not disclose whether an account exists.
        """
        user = await User.find_one({"email": email.lower(), "is_active": True})
        if user is None:
            verify_password(password, _decoy_password_hash())
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    async def get_by_id(self, user_id: PydanticObjectId) -> User | None:
        """Load a local user by identifier."""
        return await User.get(user_id)

    async def record_login(self, user: User) -> User:
        """Stamp the moment an account most recently signed in."""
        await write_user_fields(user, last_login_at=utc_now())
        return user

    # ------------------------------------------------------------ administration
    async def list_users(
        self,
        *,
        role: UserRole | None = None,
        status: UserStatus | None = None,
        query: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[User], int]:
        """List local users filtered by role, status, and a free-text term."""
        criteria = self._list_criteria(role=role, status=status, query=query)
        total = await User.find(criteria).count()
        items = await User.find(criteria).sort("email").skip(skip).limit(limit).to_list()
        return items, total

    async def invite(
        self,
        *,
        email: str,
        display_name: str,
        role: UserRole,
        invited_by: PydanticObjectId | None,
    ) -> tuple[User, str]:
        """Create an inactive account and return its one-time invitation token."""
        normalized = email.lower().strip()
        if await User.find_one({"email": normalized}) is not None:
            msg = "A user with this email already exists"
            raise UserAlreadyExistsError(msg)

        token = secrets.token_urlsafe(_INVITATION_TOKEN_BYTES)
        user = User(
            email=normalized,
            display_name=display_name.strip(),
            # No usable password until the invitation is accepted.
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role=role,
            is_active=False,
            status=UserStatus.INVITED,
            invited_by=invited_by,
            invitation_token_hash=hash_opaque_token(token),
            invitation_expires_at=utc_now() + timedelta(days=INVITATION_LIFETIME_DAYS),
        )
        try:
            await user.insert()
        except DuplicateKeyError as exc:
            msg = "A user with this email already exists"
            raise UserAlreadyExistsError(msg) from exc
        return user, token

    async def resend_invitation(self, user_id: PydanticObjectId) -> tuple[User, str]:
        """Replace a pending invitation token and return the new one."""
        user = await self._require_user(user_id)
        if user.status is not UserStatus.INVITED:
            msg = "This account has already accepted its invitation"
            raise InvitationError(msg)

        token = secrets.token_urlsafe(_INVITATION_TOKEN_BYTES)
        user.invitation_token_hash = hash_opaque_token(token)
        await write_user_fields(
            user,
            invitation_token_hash=user.invitation_token_hash,
            invitation_expires_at=utc_now() + timedelta(days=INVITATION_LIFETIME_DAYS),
        )
        return user, token

    async def accept_invitation(
        self,
        *,
        token: str,
        password: str,
        display_name: str | None = None,
    ) -> User:
        """Activate an invited account with the password its owner chose."""
        digest = hash_opaque_token(token)
        user = await User.find_one({"invitation_token_hash": digest})
        invalid = "This invitation is invalid or has expired"
        if user is None or user.invitation_token_hash is None:
            raise InvitationError(invalid)
        if not hmac.compare_digest(user.invitation_token_hash, digest):
            raise InvitationError(invalid)
        if user.status is not UserStatus.INVITED:
            raise InvitationError(invalid)
        expires_at = user.invitation_expires_at
        if expires_at is None or _aware_expired(expires_at):
            raise InvitationError(invalid)

        changes: dict[str, object] = {
            "invitation_token_hash": None,
            "invitation_expires_at": None,
            "is_active": True,
            "status": UserStatus.ACTIVE,
            "password_hash": hash_password(password),
            "password_changed_at": utc_now(),
        }
        # Only a name the invitation's owner actually chose. Naming the field
        # unconditionally wrote back the one loaded a moment earlier, so an
        # administrator who renamed the account in between had their change
        # undone by someone accepting an invitation to it.
        chosen = (display_name or "").strip()
        if chosen:
            changes["display_name"] = chosen
        await write_user_fields(user, **changes)
        return user

    async def update_user(
        self,
        user_id: PydanticObjectId,
        *,
        actor: User,
        display_name: str | None = None,
        role: UserRole | None = None,
    ) -> User:
        """Change a user's display name and role within the last-admin rules.

        Only what the patch supplied is written. Naming both fields every time
        put back whatever this request happened to load: a rename that started
        before an administrator was demoted, and finished after, restored the
        role it had read on the way in.
        """
        user = await self._require_user(user_id)
        changes: dict[str, object] = {}
        if role is not None and role is not user.role:
            await self._guard_administrator_removal(user, actor=actor)
            user.role = role
            changes["role"] = role
        if display_name is not None and display_name.strip():
            user.display_name = display_name.strip()
            changes["display_name"] = user.display_name
        if changes:
            await write_user_fields(user, **changes)
        return user

    async def deactivate(self, user_id: PydanticObjectId, *, actor: User) -> User:
        """Disable an account, keeping at least one active administrator."""
        user = await self._require_user(user_id)
        if not user.is_active:
            return user
        await self._guard_administrator_removal(user, actor=actor)
        await write_user_fields(user, is_active=False, status=UserStatus.DEACTIVATED)
        return user

    async def activate(self, user_id: PydanticObjectId) -> User:
        """Re-enable a deactivated account."""
        user = await self._require_user(user_id)
        if user.status is UserStatus.INVITED:
            msg = "This account has not accepted its invitation yet"
            raise InvitationError(msg)
        await write_user_fields(user, is_active=True, status=UserStatus.ACTIVE)
        return user

    # ---------------------------------------------------------------- internals
    async def _require_user(self, user_id: PydanticObjectId) -> User:
        user = await User.get(user_id)
        if user is None:
            msg = "User not found"
            raise UserNotFoundError(msg)
        return user

    async def _guard_administrator_removal(self, user: User, *, actor: User) -> None:
        """Refuse changes that strip the deployment of its administrators."""
        if user.role is not UserRole.ADMINISTRATOR:
            return
        if actor.id is not None and user.id == actor.id:
            msg = "You cannot remove your own administrator access"
            raise LastAdministratorError(msg)
        remaining = await User.find(
            {
                "role": UserRole.ADMINISTRATOR.value,
                "is_active": True,
                "_id": {"$ne": user.id},
            },
        ).count()
        if remaining == 0:
            msg = "At least one active administrator must remain"
            raise LastAdministratorError(msg)

    @staticmethod
    def _list_criteria(
        *,
        role: UserRole | None,
        status: UserStatus | None,
        query: str | None,
    ) -> dict[str, Any]:
        criteria: dict[str, Any] = {}
        if role is not None:
            criteria["role"] = role.value
        if status is not None:
            criteria["status"] = status.value
        term = (query or "").strip()
        if term:
            pattern = re.escape(term)
            criteria["$or"] = [
                {"email": {"$regex": pattern, "$options": "i"}},
                {"display_name": {"$regex": pattern, "$options": "i"}},
            ]
        return criteria


def _aware_expired(value: datetime) -> bool:
    """Report whether a stored expiry, possibly naive from MongoDB, has passed."""
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment <= utc_now()
