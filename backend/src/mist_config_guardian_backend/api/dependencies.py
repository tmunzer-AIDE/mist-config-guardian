"""FastAPI service and authorization dependencies."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.models.organization import Organization
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.auth import AccessTokenError, decode_access_token
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationService,
)
from mist_config_guardian_backend.services.organizations import OrganizationService
from mist_config_guardian_backend.services.restore_authorization import RestoreAuthorizationService
from mist_config_guardian_backend.services.sessions import CsrfError, SessionService
from mist_config_guardian_backend.services.users import UserService
from mist_config_guardian_backend.services.webhooks import WebhookIngestionService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

_ROLE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 0,
    UserRole.OPERATOR: 1,
    UserRole.ADMINISTRATOR: 2,
}


def get_user_service(settings: Annotated[Settings, Depends(get_settings)]) -> UserService:
    """Build the local user service."""
    return UserService(settings)


def get_credential_vault(settings: Annotated[Settings, Depends(get_settings)]) -> CredentialVault:
    """Build the encrypted credential vault."""
    return CredentialVault(settings)


def get_mist_verification_service() -> MistVerificationService:
    """Build the read-only Mist verification integration."""
    return MistVerificationService()


def get_session_service(settings: Annotated[Settings, Depends(get_settings)]) -> SessionService:
    """Build the revocable browser-session service."""
    return SessionService(settings)


def get_organization_service(
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
    mist: Annotated[MistVerificationService, Depends(get_mist_verification_service)],
) -> OrganizationService:
    """Build the organization application service."""
    return OrganizationService(vault, mist)


def get_application_configuration_service(
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
) -> ApplicationConfigurationService:
    """Build the administrator-managed application configuration service."""
    return ApplicationConfigurationService(vault)


def get_webhook_ingestion_service(
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
) -> WebhookIngestionService:
    """Build the durable webhook ingestion service."""
    return WebhookIngestionService(vault)


def get_restore_authorization_service(
    settings: Annotated[Settings, Depends(get_settings)],
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
    mist: Annotated[MistVerificationService, Depends(get_mist_verification_service)],
) -> RestoreAuthorizationService:
    """Build the delegated restore authorization service."""
    return RestoreAuthorizationService(settings, vault, mist)


async def get_current_user(
    request: Request,
    token: Annotated[str | None, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
    users: Annotated[UserService, Depends(get_user_service)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> User:
    """Resolve the current user from a session cookie or bearer access token."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        session_user = await sessions.resolve_request_user(request)
    except CsrfError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if session_user is not None:
        return session_user

    if token is None:
        raise unauthorized
    try:
        claims = decode_access_token(token, settings)
    except AccessTokenError as exc:
        raise unauthorized from exc

    user = await users.get_by_id(claims.subject)
    if user is None or not user.is_active:
        raise unauthorized
    return user


def _require_role(minimum: UserRole):  # noqa: ANN202 - FastAPI dependency factory
    """Build a dependency that requires at least the given role."""

    async def dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{minimum.value.capitalize()} role required",
            )
        return user

    return dependency


require_viewer = _require_role(UserRole.VIEWER)
require_operator = _require_role(UserRole.OPERATOR)
require_administrator = _require_role(UserRole.ADMINISTRATOR)


async def require_organization(
    organization_id: PydanticObjectId,
    _user: Annotated[User, Depends(require_viewer)],
) -> Organization:
    """Load an organization the caller is allowed to read, or fail with 404."""
    organization = await Organization.get(organization_id)
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )
    return organization


async def reject_historical_context(
    as_of: Annotated[str | None, Header(alias="X-Config-Guardian-As-Of")] = None,
) -> None:
    """Refuse a write submitted while the client is browsing a past point in time.

    The header is set by the browser shell whenever the time-travel bar is not at
    "now". Rejecting it server-side keeps historical browsing from silently
    producing writes derived from a reconstructed past state.
    """
    if as_of:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Write operations are disabled while viewing a historical point in time",
        )
