"""User administration endpoints."""

import logging
from typing import Annotated, Literal

from beanie import PydanticObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status

from mist_config_guardian_backend.api.dependencies import (
    get_application_configuration_service,
    get_session_service,
    get_user_service,
    require_administrator,
)
from mist_config_guardian_backend.config import Settings, get_settings
from mist_config_guardian_backend.integrations.smtp import MailSender, SendOutcome, SmtpMailSender
from mist_config_guardian_backend.models.user import User, UserRole, UserStatus
from mist_config_guardian_backend.schemas.auth import AcceptInvitationRequest, UserResponse
from mist_config_guardian_backend.schemas.users import (
    UserInviteRequest,
    UserInviteResponse,
    UserListResponse,
    UserSummaryResponse,
    UserUpdateRequest,
)
from mist_config_guardian_backend.security.credentials import CredentialDecryptionError
from mist_config_guardian_backend.services.application_configuration import (
    ApplicationConfigurationService,
)
from mist_config_guardian_backend.services.invitation_email import (
    activation_url,
    build_invitation_message,
)
from mist_config_guardian_backend.services.passkeys import PasskeyService, get_passkey_service
from mist_config_guardian_backend.services.sessions import SessionService
from mist_config_guardian_backend.services.throttling import ThrottleService, get_throttle_service, reserve_or_raise
from mist_config_guardian_backend.services.users import (
    INVITATION_LIFETIME_DAYS,
    InvitationError,
    LastAdministratorError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UserService,
)

router = APIRouter(prefix="/users")

logger = logging.getLogger(__name__)


def _not_found(exc: UserNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


async def get_mail_sender(
    service: Annotated[ApplicationConfigurationService, Depends(get_application_configuration_service)],
) -> MailSender | None:
    """Build a sender from the stored settings, or ``None`` when email is off.

    A stored SMTP password that fails to decrypt - corrupted, or encrypted
    under a key that has since rotated - is a broken mail configuration, not
    a reason to refuse the request that depends on this. It runs outside
    ``_deliver``'s protection, as a dependency resolved before the route body,
    so it degrades to ``None`` (reported as ``not_configured``) here rather
    than raising: onboarding must not 500 before an account is even created.
    """
    try:
        credentials = await service.smtp_credentials()
    except CredentialDecryptionError:
        logger.exception("Stored SMTP credential could not be decrypted; email disabled for this request")
        return None
    return SmtpMailSender(credentials) if credentials is not None else None


# The upper bound a mail server's own text may occupy in the response. This is
# a second, independent bound alongside the transport's own truncation: any
# ``MailSender`` implementation can report a ``detail``, and this is the
# boundary where it becomes part of a public API response.
_MAX_DELIVERY_DETAIL = 200


def _safe_detail(detail: str, token: str) -> str:
    """Bound and scrub server-supplied text before it reaches an administrator.

    Some SMTP servers echo a snippet of the rejected message back in their
    reply - the very message whose activation link carries the invitation
    token - so the token is scrubbed here rather than trusted to be absent.

    This is best-effort against a cooperative-but-broken server, not a
    guarantee: an exact ``str.replace`` misses a server that case-folds its
    echo, inserts a quoted-printable soft break inside the token, or quotes
    only a prefix of it. A scrub that looked total but was not would be worse
    than one whose limits are written down, so they are written down here
    instead of chasing every encoding a server might apply.
    """
    scrubbed = detail.replace(token, "[redacted]")
    return scrubbed[:_MAX_DELIVERY_DETAIL]


async def _deliver(
    user: User,
    token: str,
    settings: Settings,
    sender: MailSender | None,
    inviter: str | None,
) -> UserInviteResponse:
    """Send the invitation and apply the delivery rule to what happened.

    The credential is withheld only once positive SMTP acceptance was
    observed; every other outcome, including one this deployment cannot even
    attempt, returns it so an administrator is never left holding a rotated
    token nobody can act on.
    """
    base_url = settings.public_base_url
    link = activation_url(base_url, token) if base_url else None
    status_value: Literal["sent", "uncertain", "not_configured", "failed"] = "not_configured"
    detail: str | None = None
    if sender is not None and link is not None:
        message = build_invitation_message(
            app_name=settings.app_name,
            inviter=inviter,
            activation_link=link,
            expires_in_days=INVITATION_LIFETIME_DAYS,
        )
        try:
            outcome = await sender.send(to=user.email, subject=message.subject, text=message.text, html=message.html)
        except Exception:
            # A blanket catch is deliberate: an unexpected escape cannot rule out
            # that the body was written, so this is uncertain rather than failed -
            # never a 500 that loses the account. Logging it via ``logger.exception``
            # is what lets Ruff's BLE001 accept the catch without a suppression.
            logger.exception("Invitation sender raised for %s", user.email)
            outcome = SendOutcome("uncertain", "The mail transport failed unexpectedly.")
        status_value = outcome.status
        detail = _safe_detail(outcome.detail, token) if outcome.detail else None
    elif sender is not None:
        # Email is configured, but no activation link could be built. Saying
        # so here is what stops an administrator from mistaking this for an
        # SMTP problem when it is an unresolved `public_base_url` instead.
        detail = (
            "No activation link could be built: the application has no resolvable "
            "public base URL. Set PUBLIC_BASE_URL, or configure exactly one CORS origin."
        )
    logger.info("Invitation for %s: %s", user.email, status_value)
    delivered = status_value == "sent"
    return UserInviteResponse(
        user=UserSummaryResponse.from_document(user),
        invitation_expires_at=user.invitation_expires_at,
        delivery=status_value,
        invitation_token=None if delivered else token,
        invitation_url=None if delivered else link,
        delivery_detail=detail,
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
async def invite_user(  # noqa: PLR0913, PLR0917 - one dependency per collaborator the delivery rule needs
    payload: UserInviteRequest,
    users: Annotated[UserService, Depends(get_user_service)],
    administrator: Annotated[User, Depends(require_administrator)],
    settings: Annotated[Settings, Depends(get_settings)],
    throttle: Annotated[ThrottleService, Depends(get_throttle_service)],
    sender: Annotated[MailSender | None, Depends(get_mail_sender)],
) -> UserInviteResponse:
    """Invite a new local user and attempt to deliver its activation link.

    The credential is withheld only once positive SMTP acceptance was
    observed; every other outcome returns it so an administrator can always
    share it out of band instead.
    """
    if administrator.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authenticated administrator is missing an identifier",
        )
    await reserve_or_raise(throttle, throttle.invitation_sender(administrator.id))
    try:
        user, token = await users.invite(
            email=str(payload.email),
            display_name=payload.display_name,
            role=payload.role,
            invited_by=administrator.id,
        )
    except UserAlreadyExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _deliver(user, token, settings, sender, administrator.display_name)


@router.post("/{user_id}/resend-invitation")
async def resend_invitation(  # noqa: PLR0913, PLR0917 - one dependency per collaborator the delivery rule needs
    user_id: PydanticObjectId,
    users: Annotated[UserService, Depends(get_user_service)],
    administrator: Annotated[User, Depends(require_administrator)],
    settings: Annotated[Settings, Depends(get_settings)],
    throttle: Annotated[ThrottleService, Depends(get_throttle_service)],
    sender: Annotated[MailSender | None, Depends(get_mail_sender)],
) -> UserInviteResponse:
    """Issue a fresh invitation token for a user who has not accepted yet.

    Both scopes are reserved before the token is rotated: a refusal must
    leave the previous token, still in flight to a legitimate invitee, valid.
    """
    if administrator.id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authenticated administrator is missing an identifier",
        )
    await reserve_or_raise(
        throttle,
        throttle.invitation_sender(administrator.id),
        throttle.invitation_target(user_id),
    )
    try:
        user, token = await users.resend_invitation(user_id)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except InvitationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _deliver(user, token, settings, sender, administrator.display_name)


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
    passkeys: Annotated[PasskeyService, Depends(get_passkey_service)],
) -> UserSummaryResponse:
    """Disable an account, sign out every session it holds, and revoke its passkeys.

    Deactivation is the remediation an administrator has when an account is
    compromised. Sessions end and passkeys — credentials that would otherwise
    outlive a password change — are removed, so reactivating the account later
    starts it with the password alone.
    """
    try:
        user = await users.deactivate(user_id, actor=administrator)
    except UserNotFoundError as exc:
        raise _not_found(exc) from exc
    except LastAdministratorError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if user.id is not None:
        await sessions.revoke_all(user.id)
        await passkeys.revoke_all(user.id)
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
