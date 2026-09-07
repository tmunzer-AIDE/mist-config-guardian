"""Local authentication endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from mist_config_guardian_backend.api.dependencies import get_current_user, get_user_service
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.user import User
from mist_config_guardian_backend.schemas.auth import AccessTokenResponse, BootstrapAdminRequest, UserResponse
from mist_config_guardian_backend.security.auth import create_access_token
from mist_config_guardian_backend.services.users import (
    BootstrapClosedError,
    InvalidBootstrapTokenError,
    UserAlreadyExistsError,
    UserService,
)

router = APIRouter(prefix="/auth")


@router.post("/bootstrap", status_code=status.HTTP_201_CREATED)
async def bootstrap_administrator(
    request: BootstrapAdminRequest,
    users: Annotated[UserService, Depends(get_user_service)],
) -> UserResponse:
    """Create the first local administrator."""
    try:
        user = await users.bootstrap_administrator(request)
    except BootstrapClosedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except InvalidBootstrapTokenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return UserResponse.from_document(user)


@router.post("/login")
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    users: Annotated[UserService, Depends(get_user_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AccessTokenResponse:
    """Authenticate a local account."""
    user = await users.authenticate(form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, expires_in = create_access_token(user, settings)
    return AccessTokenResponse(access_token=token, expires_in=expires_in)


@router.get("/me")
async def current_user(user: Annotated[User, Depends(get_current_user)]) -> UserResponse:
    """Return the current local user."""
    return UserResponse.from_document(user)
