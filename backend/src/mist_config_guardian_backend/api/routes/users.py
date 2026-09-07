"""User administration endpoints."""

from typing import Annotated

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status

from mist_config_guardian_backend.api.dependencies import (
    get_session_service,
    get_user_service,
    require_administrator,
)
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus
from mist_config_guardian_backend.schemas.auth import AcceptInvitationRequest, UserResponse
from mist_config_guardian_backend.schemas.users import (
    UserInviteRequest,
    UserInviteResponse,
    UserListResponse,
    UserSummaryResponse,
    UserUpdateRequest,
)
from mist_config_guardian_backend.services.sessions import SessionService
from mist_config_guardian_backend.services.users import (
    InvitationError,
    LastAdministratorError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UserService,
)

router = APIRouter(prefix="/users")


def _not_found(exc: UserNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def _invitation_response(
    user: User,
    token: str,
    settings: Settings,
) -> UserInviteResponse:
    """Return an invitation, exposing its token only outside production."""
    return UserInviteResponse(
        user=UserSummaryResponse.from_document(user),
        invitation_expires_at=user.invitation_expires_at,
        invitation_token=token if settings.environment != "production" else None,
    )


@router.post("/accept-invitation")
async def accept_invitation(
    payload: AcceptInvitationRequest,
    users: Annotated[UserService, Depends(get_user_service)],
) -> UserResponse:
    """Activate an invited account with the password its owner chose.

    This endpoint is unauthenticated: the invitation token is the credential.
    """
    try:
        user = await users.accept_invitation(
            token=payload.token,
            password=payload.password.get_secret_value(),
            display_name=payload.display_name,
        )
    except InvitationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return UserResponse.from_document(user)


@router.get("")
async def list_users(  # noqa: PLR0913, PLR0917 - filters and pagination are separate query parameters
    users: Annotated[UserService, Depends(get_user_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
    role: Annotated[UserRole | None, Query()] = None,
    account_status: Annotated[UserStatus | None, Query(alias="status")] = None,
    q: Annotated[str | None, Query(max_length=120)] = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> UserListResponse:
    """List local users filtered by role, status, and a free-text search term."""
    items, total = await users.list_users(
        role=role,
        status=account_status,
        query=q,
        skip=skip,
        limit=limit,
    )
    return UserListResponse(
        items=[UserSummaryResponse.from_document(item) for item in items],
        total=total,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def invite_user(
    payload: UserInviteRequest,
    users: Annotated[UserService, Depends(get_user_service)],
    administrator: Annotated[User, Depends(require_administrator)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> UserInviteResponse:
    """Invite a new local user.

    Email delivery is not implemented: this deployment has no mail transport.
    Outside production the invitation token is returned here so it can be shared
    out of band; in production it is withheld.
    """
    try:
        user, token = await users.invite(
            email=str(payload.email),
            display_name=payload.display_name,
            role=payload.role,
            invited_by=administrator.id,
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _invitation_response(user, token, settings)


@router.post("/{user_id}/resend-invitation")
async def resend_invitation(
    user_id: PydanticObjectId,
    users: Annotated[UserService, Depends(get_user_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> UserInviteResponse:
    """Issue a fresh invitation token for a user who has not accepted yet."""
    try:
        user, token = await users.resend_invitation(user_id)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except InvitationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return _invitation_response(user, token, settings)


@router.patch("/{user_id}")
async def update_user(
    user_id: PydanticObjectId,
    payload: UserUpdateRequest,
    users: Annotated[UserService, Depends(get_user_service)],
    administrator: Annotated[User, Depends(require_administrator)],
) -> UserSummaryResponse:
    """Change a user's display name or role.

    An administrator cannot remove their own administrator role, and the last
    active administrator cannot be demoted.
    """
    try:
        user = await users.update_user(
            user_id,
            actor=administrator,
            display_name=payload.display_name,
            role=payload.role,
        )
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except LastAdministratorError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return UserSummaryResponse.from_document(user)


@router.post("/{user_id}/deactivate")
async def deactivate_user(
    user_id: PydanticObjectId,
    users: Annotated[UserService, Depends(get_user_service)],
    administrator: Annotated[User, Depends(require_administrator)],
    sessions: Annotated[SessionService, Depends(get_session_service)],
) -> UserSummaryResponse:
    """Disable an account and sign out every session it holds."""
    try:
        user = await users.deactivate(user_id, actor=administrator)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except LastAdministratorError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if user.id is not None:
        await sessions.revoke_all(user.id)
    return UserSummaryResponse.from_document(user)


@router.post("/{user_id}/activate")
async def activate_user(
    user_id: PydanticObjectId,
    users: Annotated[UserService, Depends(get_user_service)],
    _administrator: Annotated[User, Depends(require_administrator)],
) -> UserSummaryResponse:
    """Re-enable a deactivated account."""
    try:
        user = await users.activate(user_id)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except InvitationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return UserSummaryResponse.from_document(user)
