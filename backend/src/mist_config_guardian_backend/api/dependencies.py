"""FastAPI service and authorization dependencies."""

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.mist import MistVerificationService
from mist_config_guardian_backend.models.user import User, UserRole
from mist_config_guardian_backend.security.auth import AccessTokenError, decode_access_token
from mist_config_guardian_backend.security.credentials import CredentialVault
from mist_config_guardian_backend.services.organizations import OrganizationService
from mist_config_guardian_backend.services.restore_authorization import RestoreAuthorizationService
from mist_config_guardian_backend.services.users import UserService
from mist_config_guardian_backend.services.webhooks import WebhookIngestionService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_user_service(settings: Annotated[Settings, Depends(get_settings)]) -> UserService:
    """Build the local user service."""
    return UserService(settings)


def get_credential_vault(settings: Annotated[Settings, Depends(get_settings)]) -> CredentialVault:
    """Build the encrypted credential vault."""
    return CredentialVault(settings)


def get_mist_verification_service() -> MistVerificationService:
    """Build the read-only Mist verification integration."""
    return MistVerificationService()


def get_organization_service(
    vault: Annotated[CredentialVault, Depends(get_credential_vault)],
    mist: Annotated[MistVerificationService, Depends(get_mist_verification_service)],
) -> OrganizationService:
    """Build the organization application service."""
    return OrganizationService(vault, mist)


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
    token: Annotated[str, Depends(oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
    users: Annotated[UserService, Depends(get_user_service)],
) -> User:
    """Resolve and validate the current local user."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_access_token(token, settings)
    except AccessTokenError as exc:
        raise unauthorized from exc

    user = await users.get_by_id(claims.subject)
    if user is None or not user.is_active:
        raise unauthorized
    return user


async def require_administrator(user: Annotated[User, Depends(get_current_user)]) -> User:
    """Require an active local administrator."""
    if user.role is not UserRole.ADMINISTRATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required",
        )
    return user
