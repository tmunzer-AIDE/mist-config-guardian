"""Local user lifecycle service."""

import secrets

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from mist_config_guardian_backend.config import Settings
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.schemas.auth import BootstrapAdminRequest
from mist_config_guardian_backend.security.auth import hash_password, verify_password


class BootstrapClosedError(ValueError):
    """Raised when first-admin bootstrap has already completed."""


class InvalidBootstrapTokenError(ValueError):
    """Raised when the bootstrap secret is invalid."""


class UserAlreadyExistsError(ValueError):
    """Raised when a local user email already exists."""


class UserService:
    """Manage local users and credential verification."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def bootstrap_administrator(self, request: BootstrapAdminRequest) -> User:
        """Create the first local administrator exactly once."""
        if await User.count() > 0:
            msg = "Administrator bootstrap is already complete"
            raise BootstrapClosedError(msg)

        expected = self._settings.bootstrap_admin_token.get_secret_value()
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
        """Authenticate an active local user."""
        user = await User.find_one({"email": email.lower(), "is_active": True})
        if user is None or not verify_password(password, user.password_hash):
            return None
        return user

    async def get_by_id(self, user_id: PydanticObjectId) -> User | None:
        """Load a local user by identifier."""
        return await User.get(user_id)
